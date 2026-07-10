// Lampa Downloader — agent (headless core).
// Holds an outbound WSS to the relay, receives E2E-encrypted jobs,
// downloads via an embedded engine into categorized folders,
// and pushes content-free progress back. No home IP ever leaves.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)

// ---------- config ----------

type Config struct {
	Priv        string       `json:"priv"`         // base64 X25519 private
	Pub         string       `json:"pub"`          // base64 X25519 public
	DownloadDir string       `json:"download_dir"` // base folder; categories go under it
	KeepSeeding bool         `json:"keep_seeding"` // false = stop seeding when complete
	Trusted     []string     `json:"trusted"`      // base64 plugin public keys
	Pending     []PendingJob `json:"pending"`      // active downloads, re-added on startup
}

// PendingJob is persisted so an interrupted download resumes after a restart
// (part files hold the data; re-adding rechecks and continues from disk).
type PendingJob struct {
	Magnet string `json:"magnet"`
	Dir    string `json:"dir"`
	Name   string `json:"name"`
}

var magnetRe = regexp.MustCompile(`^magnet:\?xt=urn:btih:[0-9A-Fa-f]{40}([0-9A-Za-z]{32})?.*`)

func deriveCode(pub []byte) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(h[:4])%1000000)
}
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func unb64(s string) []byte {
	d, _ := base64.StdEncoding.DecodeString(s)
	return d
}

// category whitelist -> folder name. Raw category never touches the path.
var categoryDir = map[string]string{
	"movies": "Movies",
	"shows":  "Shows",
}

// ---------- agent ----------

type Job struct {
	id     string
	name   string // kept locally for logs only; never sent to relay
	magnet string // for pending removal on cancel
	t      *torrent.Torrent
	state  string // connecting|downloading|seeding|done
	pct    int
}

type Agent struct {
	cfgPath string
	cfg     Config
	priv    *[32]byte
	pub     *[32]byte
	code    string

	tc *torrent.Client

	mu      sync.Mutex
	jobs    map[string]*Job
	trusted map[string]bool
	relayUp bool
	uiToken string

	outCh chan map[string]any // to current ws writer (best-effort)
}

func loadOrInitConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("config parse: %w", err)
		}
		return c, nil
	}
	// fresh: generate keypair
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return c, err
	}
	c.Priv = b64(priv[:])
	c.Pub = b64(pub[:])
	home, _ := os.UserHomeDir()
	c.DownloadDir = filepath.Join(home, "Downloads", "Lampa")
	c.KeepSeeding = false
	return c, nil
}

func (a *Agent) saveConfig() {
	a.cfg.Trusted = a.cfg.Trusted[:0]
	for k := range a.trusted {
		a.cfg.Trusted = append(a.cfg.Trusted, k)
	}
	b, _ := json.MarshalIndent(a.cfg, "", "  ")
	tmp := a.cfgPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		log.Printf("config save: %v", err)
		return
	}
	os.Rename(tmp, a.cfgPath)
}

func (a *Agent) addPending(magnet, dir, name string) {
	a.mu.Lock()
	for _, p := range a.cfg.Pending {
		if p.Magnet == magnet {
			a.mu.Unlock()
			return
		}
	}
	a.cfg.Pending = append(a.cfg.Pending, PendingJob{Magnet: magnet, Dir: dir, Name: name})
	a.mu.Unlock()
	a.saveConfig()
}

func (a *Agent) removePending(magnet string) {
	a.mu.Lock()
	out := a.cfg.Pending[:0]
	for _, p := range a.cfg.Pending {
		if p.Magnet != magnet {
			out = append(out, p)
		}
	}
	a.cfg.Pending = out
	a.mu.Unlock()
	a.saveConfig()
}

func (a *Agent) send(m map[string]any) {
	select {
	case a.outCh <- m:
	default: // writer gone or slow: drop; status is periodic and self-heals
	}
}

// ---------- relay connection ----------

func (a *Agent) connectLoop(wsURL string) {
	backoff := time.Second
	for {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("relay dial failed: %v (retry in %s)", err, backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		log.Printf("relay connected: %s", wsURL)
		backoff = time.Second
		a.mu.Lock()
		a.relayUp = true
		a.mu.Unlock()
		a.handleConn(conn)
		a.mu.Lock()
		a.relayUp = false
		a.mu.Unlock()
		log.Printf("relay disconnected, reconnecting")
	}
}

func (a *Agent) handleConn(conn *websocket.Conn) {
	defer conn.Close()
	done := make(chan struct{})

	// hello first, directly (ordering guaranteed)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(map[string]any{"type": "hello", "pub": a.cfg.Pub, "id": a.code}); err != nil {
		return
	}

	// writer pump
	go func() {
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-done:
				return
			case m := <-a.outCh:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteJSON(m); err != nil {
					return
				}
			case <-ping.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})

	for {
		var m map[string]any
		if err := conn.ReadJSON(&m); err != nil {
			close(done)
			return
		}
		switch m["type"] {
		case "paired":
			a.onPaired(str(m["pub"]))
		case "job":
			a.onJob(m)
		}
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func (a *Agent) onPaired(pubB string) {
	if len(unb64(pubB)) != 32 {
		return
	}
	a.mu.Lock()
	fresh := !a.trusted[pubB]
	a.trusted[pubB] = true
	a.mu.Unlock()
	if fresh {
		a.saveConfig()
		log.Printf("paired with a new plugin (trusted key added)")
	} else {
		log.Printf("re-paired with a known plugin")
	}
}

func (a *Agent) onJob(m map[string]any) {
	pubB := str(m["pub"])
	a.mu.Lock()
	trusted := a.trusted[pubB]
	a.mu.Unlock()
	if !trusted {
		log.Printf("job from untrusted key -> dropped")
		return
	}
	var nonce [24]byte
	nb := unb64(str(m["nonce"]))
	if len(nb) != 24 {
		return
	}
	copy(nonce[:], nb)
	var peer [32]byte
	copy(peer[:], unb64(pubB))

	pt, ok := box.Open(nil, unb64(str(m["ct"])), &nonce, &peer, a.priv)
	if !ok {
		log.Printf("job decrypt failed -> dropped")
		return
	}
	var payload struct {
		Magnet string `json:"magnet"`
		Cat    string `json:"cat"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(pt, &payload); err != nil {
		log.Printf("job payload parse failed -> dropped")
		return
	}
	if !magnetRe.MatchString(payload.Magnet) {
		log.Printf("job magnet rejected (not a magnet URI) -> dropped")
		return
	}
	dir, ok := categoryDir[payload.Cat]
	if !ok {
		dir = "Other" // unknown category never becomes raw path input
	}
	id := str(m["id"])
	go a.startDownload(id, payload.Magnet, dir, payload.Name)
}

// ---------- torrent engine ----------

// fileStorage uses plain file I/O with in-memory piece completion.
// This avoids the bbolt (.torrent.bolt.db) memory-mapping that panics on
// Windows ("CreateFileMapping ... externally altered"). Part files keep
// partial data on disk, so an interrupted job resumes after a restart
// (re-hashes what's there, continues from disk).
// cancelJob stops a download, removes it, and forgets it so it won't resume.
func (a *Agent) cancelJob(id string) {
	a.mu.Lock()
	j := a.jobs[id]
	if j != nil {
		delete(a.jobs, id)
	}
	a.mu.Unlock()
	if j == nil {
		return
	}
	if j.t != nil {
		func() { defer func() { _ = recover() }(); j.t.Drop() }()
	}
	if j.magnet != "" {
		a.removePending(j.magnet)
	}
	log.Printf("job %s cancelled: %q", id, j.name)
}

// setDir changes the download folder for future downloads.
func (a *Agent) setDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("empty path")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg.DownloadDir = dir
	a.mu.Unlock()
	a.saveConfig()
	log.Printf("download dir changed: %s", dir)
	return nil
}

func fileStorage(dir string) storage.ClientImpl {
	return storage.NewFileWithCompletion(dir, storage.NewMapPieceCompletion())
}

func (a *Agent) startDownload(id, magnet, catDir, name string) {
	target := filepath.Join(a.cfg.DownloadDir, catDir)
	if err := os.MkdirAll(target, 0755); err != nil {
		log.Printf("mkdir %s: %v", target, err)
		return
	}
	spec, err := torrent.TorrentSpecFromMagnetUri(magnet)
	if err != nil {
		log.Printf("bad magnet: %v", err)
		return
	}
	spec.Storage = fileStorage(target)

	t, _, err := a.tc.AddTorrentSpec(spec)
	if err != nil {
		log.Printf("add torrent: %v", err)
		return
	}

	a.addPending(magnet, catDir, name) // persist so a restart resumes it

	j := &Job{id: id, name: name, magnet: magnet, t: t, state: "connecting"}
	a.mu.Lock()
	a.jobs[id] = j
	a.mu.Unlock()
	log.Printf("job %s queued: %q -> %s", id, name, target)

	<-t.GotInfo()
	t.DownloadAll()
	a.setState(j, "downloading")

	total := t.Length()
	for {
		done := t.BytesCompleted()
		pct := 0
		if total > 0 {
			pct = int(done * 100 / total)
		}
		a.mu.Lock()
		j.pct = pct
		a.mu.Unlock()
		if done >= total && total > 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}

	a.removePending(magnet) // done downloading; no longer needs resume
	if a.cfg.KeepSeeding {
		a.setState(j, "seeding")
		log.Printf("job %s complete: %q (seeding)", id, name)
	} else {
		t.Drop() // stops seeding; files stay on disk
		a.setState(j, "done")
		log.Printf("job %s complete: %q (stopped)", id, name)
	}
}

func (a *Agent) setState(j *Job, s string) {
	a.mu.Lock()
	j.state = s
	a.mu.Unlock()
}

// ---------- status push (content-free) ----------

// printLoop shows human-readable progress of active downloads in the console.
func (a *Agent) printLoop() {
	for range time.Tick(5 * time.Second) {
		a.mu.Lock()
		jobs := make([]*Job, 0, len(a.jobs))
		for _, j := range a.jobs {
			jobs = append(jobs, j)
		}
		a.mu.Unlock()
		for _, j := range jobs {
			printJob(j)
		}
	}
}

// printJob reads torrent stats defensively: Length()/BytesCompleted() panic if
// called before metadata (GotInfo) arrives, so skip until state advances and
// recover from any panic just in case.
func printJob(j *Job) {
	defer func() { _ = recover() }()
	if j.t == nil || j.state == "done" {
		return
	}
	if j.state == "connecting" {
		log.Printf("%-11s  %s", j.state, j.name)
		return
	}
	total := j.t.Length()
	done := j.t.BytesCompleted()
	pct := 0.0
	if total > 0 {
		pct = float64(done) * 100 / float64(total)
	}
	log.Printf("%-11s %5.1f%%  (%.0f/%.0f MiB)  %s",
		j.state, pct, float64(done)/(1<<20), float64(total)/(1<<20), j.name)
}

func (a *Agent) statusLoop() {
	for range time.Tick(2 * time.Second) {
		a.mu.Lock()
		jobs := make([]map[string]any, 0, len(a.jobs))
		for _, j := range a.jobs {
			jobs = append(jobs, map[string]any{"id": j.id, "pct": j.pct, "state": j.state})
		}
		a.mu.Unlock()
		if len(jobs) > 0 {
			a.send(map[string]any{"type": "status", "jobs": jobs})
		}
	}
}

// ---------- main ----------

func main() {
	// Native panel window mode: no engine, no re-exec — just the webview.
	for _, a := range os.Args[1:] {
		if len(a) > 9 && a[:9] == "--window=" {
			runWindow(a[9:])
			return
		}
	}

	// The torrent storage package picks its file I/O in an init() that runs
	// before main(), defaulting to mmap — which panics on Windows
	// ("CreateFileMapping ... externally altered"). We can't set the env var in
	// time from here, so if it's unset we set it to "classic" and re-exec
	// ourselves once; the child sees it at init and uses plain file I/O.
	if os.Getenv("TORRENT_STORAGE_DEFAULT_FILE_IO") == "" {
		exe, err := os.Executable()
		if err != nil {
			exe = os.Args[0]
		}
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "TORRENT_STORAGE_DEFAULT_FILE_IO=classic")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
		return
	}

	defWs := "wss://relay.bwa.ad/ws"
	cfgDir, _ := os.UserConfigDir()
	defCfg := filepath.Join(cfgDir, "lampa-downloader", "agent.json")

	wsURL := flag.String("relay", defWs, "relay websocket URL")
	cfgPath := flag.String("config", defCfg, "config file path")
	dirFlag := flag.String("dir", "", "download dir (overrides config)")
	seedFlag := flag.Bool("seed", false, "keep seeding after complete (overrides config)")
	selfTest := flag.String("selftest", "", "download this magnet directly (skip relay) and print progress, for testing")
	uiAddrFlag := flag.String("ui", "127.0.0.1:47801", "web panel bind address (use 0.0.0.0:47801 for NAS/LAN access)")
	uiToken := flag.String("ui-token", "", "if set, the web panel requires this token (Basic Auth password) — recommended when bound to 0.0.0.0")
	headless := flag.Bool("headless", false, "no window/tray; run in background (for NAS/servers) — panel via browser")
	flag.Parse()

	os.MkdirAll(filepath.Dir(*cfgPath), 0700)
	cfg, err := loadOrInitConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if *dirFlag != "" {
		cfg.DownloadDir = *dirFlag
	}
	if *seedFlag {
		cfg.KeepSeeding = true
	}

	var pub, priv [32]byte
	copy(pub[:], unb64(cfg.Pub))
	copy(priv[:], unb64(cfg.Priv))

	a := &Agent{
		cfgPath: *cfgPath,
		cfg:     cfg,
		priv:    &priv,
		pub:     &pub,
		code:    deriveCode(pub[:]),
		jobs:    make(map[string]*Job),
		trusted: make(map[string]bool),
		outCh:   make(chan map[string]any, 32),
	}
	for _, k := range cfg.Trusted {
		a.trusted[k] = true
	}
	a.saveConfig() // persist freshly-generated keys / normalize

	uiAddr := *uiAddrFlag
	uiURL := "http://127.0.0.1" + uiAddr[strings.LastIndex(uiAddr, ":"):]

	// single-instance FIRST (before the engine binds any port): a second launch
	// just opens the panel window and exits, instead of crashing on a busy port.
	if *selfTest == "" {
		lock, lerr := net.Listen("tcp", "127.0.0.1:47800")
		if lerr != nil {
			openWindow(uiURL)
			return
		}
		defer lock.Close()
	}

	// torrent client (random listen port avoids fixed-port clashes)
	tcfg := torrent.NewDefaultClientConfig()
	tcfg.DataDir = cfg.DownloadDir
	tcfg.Seed = true // allow seeding; we Drop() per-torrent when KeepSeeding is off
	tcfg.ListenPort = 0
	os.MkdirAll(cfg.DownloadDir, 0755)
	tc, err := torrent.NewClient(tcfg)
	if err != nil {
		log.Fatalf("torrent client: %v", err)
	}
	a.tc = tc
	defer tc.Close()

	fmt.Println("============================================")
	fmt.Printf("  Lampa Downloader agent\n")
	fmt.Printf("  Pairing code:  %s\n", fmtCode(a.code))
	fmt.Printf("  Download dir:  %s\n", cfg.DownloadDir)
	fmt.Printf("  Keep seeding:  %v\n", cfg.KeepSeeding)
	fmt.Println("  Enter the code in Lampa to link this PC.")
	fmt.Println("============================================")

	if *selfTest != "" {
		a.runSelfTest(*selfTest)
		return
	}

	go a.statusLoop()
	go a.printLoop()

	enableAutostart()
	a.uiToken = *uiToken
	a.startUI(uiAddr)

	// resume downloads that were still active when we last exited
	a.mu.Lock()
	resume := append([]PendingJob(nil), a.cfg.Pending...)
	a.mu.Unlock()
	for _, p := range resume {
		log.Printf("resuming: %q", p.Name)
		go a.startDownload(randID(), p.Magnet, p.Dir, p.Name)
	}

	go a.connectLoop(*wsURL)
	if *headless {
		log.Printf("headless mode — panel on http://%s", uiAddr)
		select {} // NAS/server: run in background, panel via browser
	}
	runAgentGUI(a, uiURL) // windows: tray + first window (blocks); other: window + block
}

// runSelfTest downloads a magnet OR a .torrent URL directly (no relay, no
// crypto) and prints progress. Confirms the embedded engine works here.
func (a *Agent) runSelfTest(arg string) {
	target := filepath.Join(a.cfg.DownloadDir, "Movies")
	os.MkdirAll(target, 0755)

	var spec *torrent.TorrentSpec
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		fmt.Println("selftest: downloading .torrent...")
		resp, err := http.Get(arg)
		if err != nil {
			log.Fatalf("selftest: fetch .torrent: %v", err)
		}
		defer resp.Body.Close()
		mi, err := metainfo.Load(resp.Body)
		if err != nil {
			log.Fatalf("selftest: parse .torrent: %v", err)
		}
		spec = torrent.TorrentSpecFromMetaInfo(mi)
	} else {
		if !magnetRe.MatchString(arg) {
			log.Fatal("selftest: not a magnet URI or http(s) .torrent link")
		}
		var err error
		spec, err = torrent.TorrentSpecFromMagnetUri(arg)
		if err != nil {
			log.Fatalf("selftest: bad magnet: %v", err)
		}
	}
	spec.Storage = fileStorage(target)

	t, _, err := a.tc.AddTorrentSpec(spec)
	if err != nil {
		log.Fatalf("selftest: add: %v", err)
	}
	fmt.Println("selftest: fetching metadata...")
	<-t.GotInfo()
	t.DownloadAll()
	fmt.Printf("selftest: %q, %.2f MiB, downloading to %s\n",
		t.Name(), float64(t.Length())/(1<<20), target)
	total := t.Length()
	for {
		done := t.BytesCompleted()
		pct := 0.0
		if total > 0 {
			pct = float64(done) * 100 / float64(total)
		}
		fmt.Printf("\rselftest: %5.1f%%  (%.1f/%.1f MiB)   ",
			pct, float64(done)/(1<<20), float64(total)/(1<<20))
		if done >= total && total > 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Printf("\nselftest: DONE -> %s\n", target)
}

func fmtCode(c string) string {
	if len(c) == 6 {
		return c[:3] + " " + c[3:]
	}
	return c
}
