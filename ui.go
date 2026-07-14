package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

func osExit() { time.Sleep(150 * time.Millisecond); os.Exit(0) }

// startUI serves the local control panel on 127.0.0.1 only.
func (a *Agent) startUI(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.uiIndex)

	// --- read-only (GET) ---
	mux.HandleFunc("/api/state", a.uiState)
	mux.HandleFunc("/api/diag", a.uiDiag)
	mux.HandleFunc("/api/browse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(browseDir(r.URL.Query().Get("path")))
	})

	// --- mutating (POST only, same-origin) ---
	mux.HandleFunc("/api/opendir", a.mutate(a.uiOpenDir))
	mux.HandleFunc("/api/cancel", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("id"); id != "" {
			a.cancelJob(id)
		}
		w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/api/pause", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("id"); id != "" {
			a.pauseJob(id)
		}
		w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/api/resume", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("id"); id != "" {
			a.resumeJob(id)
		}
		w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/api/setdir", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		dir := r.URL.Query().Get("dir")
		w.Header().Set("Content-Type", "application/json")
		if dir == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Пустой путь"})
			return
		}
		if err := a.setDir(dir); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": dirErrRu(err)})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"dir": a.cfg.DownloadDir})
	}))
	mux.HandleFunc("/api/settings", a.mutate(a.uiSettings))
	mux.HandleFunc("/api/pickdir", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		d := pickDir()
		if d != "" {
			a.setDir(d)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"dir": a.cfg.DownloadDir})
	}))
	mux.HandleFunc("/api/device/rename", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := a.renameDevice(r.URL.Query().Get("pub"), r.URL.Query().Get("name")); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
	}))
	mux.HandleFunc("/api/device/revoke", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		a.revokeDevice(r.URL.Query().Get("pub"))
		w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/api/resetkey", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := a.resetKeys(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
	}))
	mux.HandleFunc("/api/history/clear", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		a.clearHistory()
		w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/api/pairmode", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		a.openPairWindow(pairWindowDur)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"pair_sec": a.pairWindowLeft()})
	}))
	mux.HandleFunc("/api/quit", a.mutate(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
		go osExit()
	}))

	var handler http.Handler = mux
	if a.uiToken != "" {
		handler = a.authWrap(mux)
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		a.uiPort = p // strict Origin: scheme-agnostic host AND port match
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("panel server failed: %v — панель недоступна (порт занят?)", err)
		}
	}()
}

// mutate wraps a state-changing endpoint: it must be POST and same-origin.
// This blocks CSRF — a random website can't POST here, and can't use a GET
// <img>/<script> to trigger it either (quit, cancel, setdir, etc).
func (a *Agent) mutate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !a.localOrigin(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// localOrigin allows requests from the panel itself (loopback) and rejects
// cross-site ones. GET reads are unaffected; only mutations go through here.
func (a *Agent) localOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		o = r.Header.Get("Referer")
	}
	if o == "" {
		// No Origin/Referer: same-origin fetch or a native (non-browser) client.
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return false
	}
	// A page served by ANOTHER local app (different port) is still cross-site:
	// require the exact panel port. Default ports normalize to an empty string.
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return a.uiPort == "" || port == a.uiPort
}

// authWrap requires HTTP Basic Auth (any user, password == token) when a token
// is configured — used when the panel is exposed on the LAN (NAS).
func (a *Agent) authWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || pass != a.uiToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="Lampa Downloader"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type uiJobResp struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Pct      int64  `json:"pct"`
	State    string `json:"state"`
	DoneMiB  int64  `json:"done_mib"`
	TotalMiB int64  `json:"total_mib"`
	Speed    int64  `json:"speed"` // bytes/sec
	ETA      int64  `json:"eta"`   // seconds, -1 = unknown
	Peers    int    `json:"peers"`
	Seeds    int    `json:"seeds"`
	Paused   bool   `json:"paused"`
	Err      string `json:"err,omitempty"`
}
type uiDevResp struct {
	Pub      string `json:"pub"`
	Name     string `json:"name"`
	AddedAt  int64  `json:"added_at"`
	LastSeen int64  `json:"last_seen"`
}
type uiStateResp struct {
	Code    string      `json:"code"`
	Dir     string      `json:"dir"`
	Seed    bool        `json:"seed"`
	Relay   bool        `json:"relay"`
	Version string      `json:"version"`
	Jobs    []uiJobResp `json:"jobs"`
	Devices []uiDevResp `json:"devices"`
	History []HistEntry `json:"history"`
	PairSec int         `json:"pair_sec"`  // pairing window remaining, 0 = closed
	PairN   int         `json:"pair_left"` // new-device slots left in the window
}

type uiSettingsResp struct {
	KeepSeeding bool `json:"keep_seeding"`
	Autostart   bool `json:"autostart"`
	KeepFiles   bool `json:"keep_files"`
}

// uiSettings reads the current preferences, or updates the ones passed as query
// params (?keep_seeding=1&autostart=0&delete_part=1).
// dirErrRu turns a filesystem error into a short message for the panel.
func dirErrRu(err error) string {
	switch {
	case os.IsPermission(err):
		return "Нет прав на эту папку"
	case os.IsNotExist(err):
		return "Путь не существует"
	default:
		return "Не удалось использовать папку: " + err.Error()
	}
}

func (a *Agent) uiSettings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	changed := false

	if v := q.Get("keep_seeding"); v != "" {
		a.mu.Lock()
		a.cfg.KeepSeeding = v == "1"
		a.mu.Unlock()
		changed = true
	}
	if v := q.Get("keep_files"); v != "" {
		a.mu.Lock()
		a.cfg.KeepFilesOnCancel = v == "1"
		a.mu.Unlock()
		changed = true
	}
	if v := q.Get("autostart"); v != "" {
		on := v == "1"
		a.mu.Lock()
		a.cfg.Autostart = on
		a.mu.Unlock()
		if err := setAutostart(on); err != nil {
			log.Printf("autostart: %v", err)
		}
		changed = true
	}
	if changed {
		a.saveConfig()
	}

	a.mu.Lock()
	resp := uiSettingsResp{
		KeepSeeding: a.cfg.KeepSeeding,
		Autostart:   a.cfg.Autostart,
		KeepFiles:   a.cfg.KeepFilesOnCancel,
	}
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *Agent) uiDiag(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	relay := a.relayUp
	njobs := len(a.jobs)
	ndev := len(a.devices)
	jobLines := make([]string, 0, njobs)
	for _, j := range a.jobs {
		jobLines = append(jobLines, fmt.Sprintf("  - %s | %d%% | %s", j.name, j.pct, j.state))
	}
	a.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "Lampa Downloader — диагностика\n")
	fmt.Fprintf(&b, "версия:      %s\n", version)
	fmt.Fprintf(&b, "ОС:          %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "аптайм:      %s\n", time.Since(a.started).Round(time.Second))
	fmt.Fprintf(&b, "relay:       %v\n", relay)
	fmt.Fprintf(&b, "код:         %s\n", fmtCode(a.code))
	fmt.Fprintf(&b, "папка:       %s\n", a.cfg.DownloadDir)
	fmt.Fprintf(&b, "сидирование: %v\n", a.cfg.KeepSeeding)
	fmt.Fprintf(&b, "приёмников:  %d\n", ndev)
	fmt.Fprintf(&b, "лог-файл:    %s\n", a.logPath)
	fmt.Fprintf(&b, "задач:       %d\n", njobs)
	for _, l := range jobLines {
		b.WriteString(l + "\n")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (a *Agent) uiState(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	jobs := make([]uiJobResp, 0, len(a.jobs))
	for _, j := range a.jobs {
		var pct, total, done int64
		var peers, seeds int
		if j.t != nil && j.state != "connecting" {
			func() {
				defer func() { _ = recover() }()
				total = j.t.Length()
				done = j.t.BytesCompleted()
				st := j.t.Stats()
				peers = st.ActivePeers
				seeds = st.ConnectedSeeders
			}()
		}
		if total > 0 {
			pct = done * 100 / total
		}
		eta := int64(-1)
		if j.speed > 0 && total > done {
			eta = (total - done) / j.speed
		}
		jobs = append(jobs, uiJobResp{
			ID: j.id, Name: j.name, Pct: pct, State: j.state,
			DoneMiB: done / (1 << 20), TotalMiB: total / (1 << 20),
			Speed: j.speed, ETA: eta, Peers: peers, Seeds: seeds, Paused: j.paused,
			Err: j.err,
		})
	}
	devs := make([]uiDevResp, 0, len(a.devices))
	for _, d := range a.devices {
		devs = append(devs, uiDevResp{Pub: d.Pub, Name: d.Name, AddedAt: d.AddedAt, LastSeen: d.LastSeen})
	}
	sort.Slice(devs, func(i, j int) bool {
		if devs[i].AddedAt != devs[j].AddedAt {
			return devs[i].AddedAt < devs[j].AddedAt
		}
		return devs[i].Pub < devs[j].Pub
	})
	hist := make([]HistEntry, len(a.cfg.History))
	copy(hist, a.cfg.History)
	// newest first for the panel
	for l, r := 0, len(hist)-1; l < r; l, r = l+1, r-1 {
		hist[l], hist[r] = hist[r], hist[l]
	}
	code, dir, seed := fmtCode(a.code), a.cfg.DownloadDir, a.cfg.KeepSeeding
	up := a.relayUp
	pairSec := 0
	if a.pairLeft > 0 {
		if v := int(time.Until(a.pairUntil).Seconds()); v > 0 {
			pairSec = v
		}
	}
	pairN := a.pairLeft
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uiStateResp{
		Code:    code,
		Dir:     dir,
		Seed:    seed,
		Relay:   up,
		Version: version,
		Jobs:    jobs,
		Devices: devs,
		History: hist,
		PairSec: pairSec,
		PairN:   pairN,
	})
}

func (a *Agent) uiOpenDir(w http.ResponseWriter, r *http.Request) {
	openPath(a.cfg.DownloadDir)
	w.Write([]byte("ok"))
}

func openPath(p string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", p)
	case "darwin":
		cmd = exec.Command("open", p)
	default:
		cmd = exec.Command("xdg-open", p)
	}
	_ = cmd.Start()
}

type dirEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}
type browseResp struct {
	Path   string     `json:"path"`
	Parent string     `json:"parent"`
	Up     bool       `json:"up"`
	Dirs   []dirEntry `json:"dirs"`
}

// browseDir lists subfolders of a path (or drive roots when path is empty).
func browseDir(path string) browseResp {
	var out browseResp
	if path == "" {
		for _, d := range listDrives() {
			name := strings.TrimSuffix(d, string(os.PathSeparator))
			if name == "" {
				name = d
			}
			out.Dirs = append(out.Dirs, dirEntry{Name: name, Path: d})
		}
		return out
	}
	out.Path = path
	out.Up = true
	parent := filepath.Dir(path)
	if parent == path {
		out.Parent = "" // at a drive root -> go back to drive list
	} else {
		out.Parent = parent
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, "$") || strings.HasPrefix(n, ".") {
			continue
		}
		out.Dirs = append(out.Dirs, dirEntry{Name: n, Path: filepath.Join(path, n)})
	}
	return out
}

func (a *Agent) uiIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(panelHTML))
}

//go:embed panel.html
var panelHTML string
