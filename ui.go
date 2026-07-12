package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func osExit() { time.Sleep(150 * time.Millisecond); os.Exit(0) }

// startUI serves the local control panel on 127.0.0.1 only.
func (a *Agent) startUI(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.uiIndex)
	mux.HandleFunc("/api/state", a.uiState)
	mux.HandleFunc("/api/opendir", a.uiOpenDir)
	mux.HandleFunc("/api/cancel", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id != "" {
			a.cancelJob(id)
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/pause", func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("id"); id != "" {
			a.pauseJob(id)
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/resume", func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("id"); id != "" {
			a.resumeJob(id)
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/setdir", func(w http.ResponseWriter, r *http.Request) {
		dir := r.URL.Query().Get("dir")
		if dir != "" {
			a.setDir(dir)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"dir": a.cfg.DownloadDir})
	})
	mux.HandleFunc("/api/browse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(browseDir(r.URL.Query().Get("path")))
	})
	mux.HandleFunc("/api/diag", a.uiDiag)
	mux.HandleFunc("/api/pickdir", func(w http.ResponseWriter, r *http.Request) {
		d := pickDir()
		if d != "" {
			a.setDir(d)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"dir": a.cfg.DownloadDir})
	})
	mux.HandleFunc("/api/quit", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")); go osExit() })

	var handler http.Handler = mux
	if a.uiToken != "" {
		handler = a.authWrap(mux)
	}
	go http.ListenAndServe(addr, handler)
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
}
type uiStateResp struct {
	Code    string      `json:"code"`
	Dir     string      `json:"dir"`
	Seed    bool        `json:"seed"`
	Relay   bool        `json:"relay"`
	Version string      `json:"version"`
	Jobs    []uiJobResp `json:"jobs"`
}

func (a *Agent) uiDiag(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	relay := a.relayUp
	njobs := len(a.jobs)
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
	fmt.Fprintf(&b, "приёмников:  %d\n", len(a.cfg.Trusted))
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
		})
	}
	up := a.relayUp
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uiStateResp{
		Code:    fmtCode(a.code),
		Dir:     a.cfg.DownloadDir,
		Seed:    a.cfg.KeepSeeding,
		Relay:   up,
		Version: version,
		Jobs:    jobs,
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
