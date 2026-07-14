// Lampa Downloader — agent (headless core).
// Holds an outbound WSS to the relay, receives E2E-encrypted jobs,
// downloads via an embedded engine into categorized folders,
// and pushes content-free progress back. No home IP ever leaves.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	Priv              string       `json:"priv"`                 // base64 X25519 private
	Pub               string       `json:"pub"`                  // base64 X25519 public
	DownloadDir       string       `json:"download_dir"`         // base folder; categories go under it
	KeepSeeding       bool         `json:"keep_seeding"`         // false = stop seeding when complete
	Autostart         bool         `json:"autostart"`            // launch with the OS
	KeepFilesOnCancel bool         `json:"keep_files_on_cancel"` // keep partial files when a job is cancelled (default: delete)
	Trusted           []string     `json:"trusted,omitempty"`    // LEGACY (<= v1.0.6): bare plugin keys; migrated to Devices on load
	Devices           []Device     `json:"devices"`              // paired plugins (TVs) with names and timestamps
	Pending           []PendingJob `json:"pending"`              // active downloads, re-added on startup
	History           []HistEntry  `json:"history"`              // completed downloads (newest last), capped
}

// Device is a paired plugin (a TV). Pub is the trust anchor; Name is only for
// the panel. LastSeen updates when a job/command arrives from this key.
type Device struct {
	Pub      string `json:"pub"`       // base64 plugin public key
	Name     string `json:"name"`      // user-editable label
	AddedAt  int64  `json:"added_at"`  // unix seconds
	LastSeen int64  `json:"last_seen"` // unix seconds, 0 = never
}

// HistEntry is one completed download, persisted so the list survives restarts.
type HistEntry struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`  // category folder (Movies/Shows/Other)
	MiB  int64  `json:"mib"`  // total size
	Done int64  `json:"done"` // unix seconds of completion
}

const historyCap = 50

// PendingJob is persisted so an interrupted download resumes after a restart
// (part files hold the data; re-adding rechecks and continues from disk).
type PendingJob struct {
	ID     string `json:"id,omitempty"` // stable across restarts so the TV re-links the same job
	Magnet string `json:"magnet"`
	Dir    string `json:"dir"`
	Name   string `json:"name"`
}

var (
	hex40Re = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	// base32 alphabet is A-Z and 2-7 only (no 0/1/8/9)
	b32Re = regexp.MustCompile(`^[A-Za-z2-7]{32}$`)
	// btihRe extracts the infohash for job deduplication.
	btihRe = regexp.MustCompile(`btih:([0-9A-Fa-f]{40}|[A-Za-z2-7]{32})`)
)

// validMagnet parses the URI properly (net/url) and requires at least one
// xt=urn:btih:<hash> where the hash is exactly 40 hex chars or exactly 32
// base32 chars — the two legal BTIH encodings, mutually exclusive.
func validMagnet(s string) bool {
	if !strings.HasPrefix(s, "magnet:?") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	for _, xt := range u.Query()["xt"] {
		if h, ok := strings.CutPrefix(xt, "urn:btih:"); ok {
			if hex40Re.MatchString(h) || b32Re.MatchString(h) {
				return true
			}
		}
	}
	return false
}

// infoHash returns the infohash of a magnet normalized to lowercase hex
// (base32 is decoded), or "" if none found. Two magnets with the same
// infohash are the same torrent regardless of trackers/names/encoding,
// so this is the dedup key.
func infoHash(magnet string) string {
	m := btihRe.FindStringSubmatch(magnet)
	if m == nil {
		return ""
	}
	h := m[1]
	if len(h) == 40 {
		return strings.ToLower(h)
	}
	raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(h))
	if err != nil || len(raw) != 20 {
		return ""
	}
	return hex.EncodeToString(raw)
}

func deriveCode(pub []byte) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(h[:4])%1000000)
}

// rotWriter is a tiny size-rotating log file writer (keeps one previous file).
type rotWriter struct {
	mu    sync.Mutex
	path  string
	f     *os.File
	size  int64
	limit int64
}

func newRotWriter(path string, limit int64) *rotWriter {
	w := &rotWriter{path: path, limit: limit}
	w.open()
	return w
}
func (w *rotWriter) open() {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	w.f = f
	if st, e := f.Stat(); e == nil {
		w.size = st.Size()
	}
}
func (w *rotWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return len(p), nil
	}
	if w.size+int64(len(p)) > w.limit {
		w.f.Close()
		os.Rename(w.path, w.path+".1")
		w.open()
		w.size = 0
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// setupLogging tees log output to the console and a rotating file next to the config.
func setupLogging(cfgPath string) string {
	logPath := filepath.Join(filepath.Dir(cfgPath), "agent.log")
	rw := newRotWriter(logPath, 2<<20) // 2 MiB, +1 rotated
	log.SetOutput(io.MultiWriter(os.Stderr, rw))
	return logPath
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// loopbackBind reports whether the bind address only listens on loopback.
func loopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false // can't tell -> treat as external, demand a token
	}
	return host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1"
}

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
	dir    string // category subfolder, for cleanup on cancel
	t      *torrent.Torrent
	state  string // connecting|downloading|paused|seeding|done|error
	err    string // human-readable failure reason (state == "error")
	pct    int
	paused bool

	// lifecycle: cancelled is set by cancelJob and makes the worker exit;
	// cancelCh unblocks the metadata wait; doneCh is closed by the worker on
	// exit so cancelJob can safely delete files only after it is gone.
	cancelled bool
	cancelCh  chan struct{}
	doneCh    chan struct{}

	// speed sampling
	lastBytes int64
	lastAt    time.Time
	speed     int64 // bytes/sec, smoothed
}

type Agent struct {
	cfgPath string
	cfg     Config
	priv    *[32]byte
	pub     *[32]byte
	code    string

	tc *torrent.Client

	mu       sync.Mutex
	jobs     map[string]*Job
	saveMu   sync.Mutex         // serializes config writes to disk
	cfgSeq   uint64             // bumped per snapshot (under mu)
	savedSeq uint64             // last snapshot on disk (under saveMu)
	devices  map[string]*Device // by plugin pub (base64)

	// pairing window (pairing v2): NEW devices are accepted only while the
	// window is open; already-trusted devices re-pair at any time.
	pairUntil time.Time
	pairLeft  int

	// replay protection: recently seen message nonces (base64 -> unix seconds)
	seenNonces map[string]int64
	conn       *websocket.Conn // current relay conn; closed on key reset to re-hello
	relayUp    bool
	uiToken    string
	uiPort     string // panel's own port, for the strict Origin check
	logPath    string
	started    time.Time

	outCh chan map[string]any // to current ws writer (best-effort)
}

// validKeys reports whether both keys decode to 32 bytes. Broken keys mean a
// broken identity: the pairing code and all trust are derived from them, so a
// config that fails this check is treated the same as unparseable JSON.
func validKeys(c *Config) bool {
	return len(unb64(c.Priv)) == 32 && len(unb64(c.Pub)) == 32
}

// normalizeConfig migrates legacy fields and fills safe defaults in place.
func normalizeConfig(c *Config) {
	// <= v1.0.6 stored bare keys in "trusted"; wrap them into Devices once.
	for _, k := range c.Trusted {
		dup := false
		for _, d := range c.Devices {
			if d.Pub == k {
				dup = true
				break
			}
		}
		if !dup && len(unb64(k)) == 32 {
			c.Devices = append(c.Devices, Device{
				Pub: k, Name: defaultDevName(k), AddedAt: time.Now().Unix(),
			})
		}
	}
	c.Trusted = nil
	if c.DownloadDir == "" {
		home, _ := os.UserHomeDir()
		c.DownloadDir = filepath.Join(home, "Downloads", "Lampa")
	}
	if len(c.History) > historyCap {
		c.History = c.History[len(c.History)-historyCap:]
	}
}

// defaultDevName derives a stable readable label from a plugin key ("ТВ 7725").
func defaultDevName(pubB string) string {
	p := unb64(pubB)
	if len(p) != 32 {
		return "ТВ"
	}
	return "ТВ " + deriveCode(p)[:4]
}

func loadOrInitConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err == nil {
		if jerr := json.Unmarshal(b, &c); jerr == nil && validKeys(&c) {
			normalizeConfig(&c)
			return c, nil
		}
		// Broken config (bad JSON or corrupt keys): keep the evidence next to
		// it and start fresh, instead of refusing to launch at all.
		bak := path + ".broken-" + time.Now().Format("20060102-150405")
		if werr := os.WriteFile(bak, b, 0600); werr == nil {
			log.Printf("config unreadable, backed up to %s and re-initialized", bak)
		} else {
			log.Printf("config unreadable and backup failed (%v); re-initializing", werr)
		}
		c = Config{}
	}
	// fresh: generate keypair and persist it right away, so the pairing code
	// stays the same across restarts even if we crash before the first save.
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return c, err
	}
	c.Priv = b64(priv[:])
	c.Pub = b64(pub[:])
	home, _ := os.UserHomeDir()
	c.DownloadDir = filepath.Join(home, "Downloads", "Lampa")
	c.KeepSeeding = false
	c.Autostart = true          // desktop default; can be turned off in the panel
	c.KeepFilesOnCancel = false // cancel cleans up by default

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return c, err
	}
	b, err = json.MarshalIndent(c, "", "  ")
	if err != nil {
		return c, err
	}
	if err := writeFileAtomic(path, b); err != nil {
		return c, fmt.Errorf("config save: %w", err)
	}
	return c, nil
}

// writeFileAtomic writes via tmp + fsync + rename, so a crash or power loss
// mid-write can never leave a truncated agent.json behind.
func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (a *Agent) saveConfig() {
	a.mu.Lock()
	a.cfg.Devices = a.cfg.Devices[:0]
	for _, d := range a.devices {
		a.cfg.Devices = append(a.cfg.Devices, *d)
	}
	sort.Slice(a.cfg.Devices, func(i, j int) bool { // stable file: oldest first
		if a.cfg.Devices[i].AddedAt != a.cfg.Devices[j].AddedAt {
			return a.cfg.Devices[i].AddedAt < a.cfg.Devices[j].AddedAt
		}
		return a.cfg.Devices[i].Pub < a.cfg.Devices[j].Pub
	})
	b, merr := json.MarshalIndent(a.cfg, "", "  ")
	a.cfgSeq++
	seq := a.cfgSeq
	a.mu.Unlock()
	if merr != nil {
		log.Printf("config save: %v", merr)
		return
	}
	// Serialize writers: concurrent saves shared one tmp file and could rename
	// a half-written snapshot into place. The seq check also drops a stale
	// snapshot if a newer one has already reached disk.
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	if seq <= a.savedSeq {
		return
	}
	if err := writeFileAtomic(a.cfgPath, b); err != nil {
		log.Printf("config save: %v", err)
		return
	}
	a.savedSeq = seq
}

func (a *Agent) addPending(id, magnet, dir, name string) {
	a.mu.Lock()
	for _, p := range a.cfg.Pending {
		if p.Magnet == magnet {
			a.mu.Unlock()
			return
		}
	}
	a.cfg.Pending = append(a.cfg.Pending, PendingJob{ID: id, Magnet: magnet, Dir: dir, Name: name})
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
		a.conn = conn
		a.mu.Unlock()
		a.handleConn(conn)
		a.mu.Lock()
		a.relayUp = false
		a.conn = nil
		a.mu.Unlock()
		log.Printf("relay disconnected, reconnecting")
	}
}

func (a *Agent) handleConn(conn *websocket.Conn) {
	defer conn.Close()
	done := make(chan struct{})

	// hello first, directly (ordering guaranteed); pub/code are read under the
	// lock because a key reset from the panel replaces both.
	a.mu.Lock()
	helloPub, helloCode := a.cfg.Pub, a.code
	a.mu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(map[string]any{"type": "hello", "pub": helloPub, "id": helloCode}); err != nil {
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
		case "pair": // pairing v2: relay waits for our verdict
			a.onPairRequest(m)
		case "paired": // legacy relay: no confirmation round-trip
			a.onPaired(str(m["pub"]))
		case "job":
			a.onJob(m)
		case "cmd":
			a.onCmd(m)
		}
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// Pairing window: how long the panel button opens it, how long the first-run
// grace period lasts, and how many NEW devices one window may admit.
const (
	pairWindowDur   = 10 * time.Minute
	pairFirstRunDur = 15 * time.Minute
	pairMaxAccepts  = 5
)

// openPairWindow (re)opens the pairing window for d.
func (a *Agent) openPairWindow(d time.Duration) {
	a.mu.Lock()
	a.pairUntil = time.Now().Add(d)
	a.pairLeft = pairMaxAccepts
	a.mu.Unlock()
	log.Printf("pairing window open for %s (up to %d new devices)", d, pairMaxAccepts)
}

// pairWindowLeft returns the remaining window seconds (0 = closed).
func (a *Agent) pairWindowLeft() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pairLeft <= 0 {
		return 0
	}
	left := int(time.Until(a.pairUntil).Seconds())
	if left < 0 {
		return 0
	}
	return left
}

// acceptPair decides whether to trust pubB and records it if so.
// Known devices always re-pair (plugin re-pairs after cache resets etc);
// NEW devices are admitted only through an open pairing window — this is what
// makes a leaked 6-digit code useless and makes revocation actually stick.
func (a *Agent) acceptPair(pubB string) bool {
	if len(unb64(pubB)) != 32 {
		return false
	}
	now := time.Now()
	a.mu.Lock()
	if d, known := a.devices[pubB]; known {
		d.LastSeen = now.Unix()
		a.mu.Unlock()
		a.saveConfig()
		log.Printf("re-paired with a known device")
		return true
	}
	if now.After(a.pairUntil) || a.pairLeft <= 0 {
		a.mu.Unlock()
		log.Printf("pairing rejected: window closed — press «Разрешить подключение» in the panel")
		return false
	}
	a.pairLeft--
	left := a.pairLeft
	a.devices[pubB] = &Device{Pub: pubB, Name: defaultDevName(pubB), AddedAt: now.Unix(), LastSeen: now.Unix()}
	a.mu.Unlock()
	a.saveConfig()
	log.Printf("paired with a new device (%s), window slots left: %d", defaultDevName(pubB), left)
	return true
}

// onPairRequest answers the relay's pairing-v2 confirmation round-trip.
func (a *Agent) onPairRequest(m map[string]any) {
	ok := a.acceptPair(str(m["pub"]))
	a.send(map[string]any{"type": "pair_result", "id": str(m["id"]), "ok": ok})
}

// onPaired is the legacy path (old relay pushes "paired" without asking).
// Gated by the same rules, so a leaked code can't bypass the window here.
func (a *Agent) onPaired(pubB string) {
	a.acceptPair(pubB)
}

// seenNonce records a message nonce and reports whether it was already used
// recently — a repeat means a replayed ciphertext, not an honest sender
// (nonces are 24 random bytes, collisions don't happen by accident).
func (a *Agent) seenNonce(n string) bool {
	const ttl = 600 // seconds
	now := time.Now().Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seenNonces == nil {
		a.seenNonces = make(map[string]int64)
	}
	if len(a.seenNonces) > 4096 { // memory guard: GC expired entries
		for k, ts := range a.seenNonces {
			if now-ts > ttl {
				delete(a.seenNonces, k)
			}
		}
	}
	if ts, dup := a.seenNonces[n]; dup && now-ts <= ttl {
		return true
	}
	a.seenNonces[n] = now
	return false
}

// freshTS enforces the optional timestamp inside encrypted payloads
// (plugin >= v0.17). Zero means an old plugin — allowed, the nonce cache
// still guards within the agent's uptime.
func freshTS(ts int64) bool {
	if ts == 0 {
		return true
	}
	d := time.Now().Unix() - ts
	if d < 0 {
		d = -d
	}
	return d <= 300
}

// touchDevice records activity from a paired plugin (best-effort persistence).
func (a *Agent) touchDevice(pubB string) {
	a.mu.Lock()
	d := a.devices[pubB]
	if d != nil {
		d.LastSeen = time.Now().Unix()
	}
	a.mu.Unlock()
	if d != nil {
		a.saveConfig()
	}
}

// renameDevice sets a user label for a paired device.
func (a *Agent) renameDevice(pubB, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 40 {
		return fmt.Errorf("имя: от 1 до 40 символов")
	}
	a.mu.Lock()
	d := a.devices[pubB]
	if d != nil {
		d.Name = name
	}
	a.mu.Unlock()
	if d == nil {
		return fmt.Errorf("устройство не найдено")
	}
	a.saveConfig()
	log.Printf("device renamed to %q", name)
	return nil
}

// revokeDevice removes trust: jobs and commands from this key are dropped
// from now on. Active downloads are not touched.
func (a *Agent) revokeDevice(pubB string) {
	a.mu.Lock()
	_, ok := a.devices[pubB]
	delete(a.devices, pubB)
	a.mu.Unlock()
	if ok {
		a.saveConfig()
		log.Printf("device access revoked")
	}
}

// resetKeys generates a fresh identity: new pairing code, all devices revoked.
// The relay connection is closed so the reconnect re-hellos with the new code.
func (a *Agent) resetKeys() error {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg.Priv, a.cfg.Pub = b64(priv[:]), b64(pub[:])
	a.priv, a.pub = priv, pub
	a.code = deriveCode(pub[:])
	a.devices = make(map[string]*Device)
	conn := a.conn
	a.mu.Unlock()
	a.saveConfig()
	if conn != nil {
		conn.Close() // connectLoop redials and registers the new code
	}
	log.Printf("keys reset: new pairing code, all devices revoked")
	return nil
}

// onCmd handles a control command from a paired plugin (pause/resume/cancel).
// Same trust + E2E rules as jobs: unknown keys and bad ciphertext are dropped.
func (a *Agent) onCmd(m map[string]any) {
	pubB := str(m["pub"])
	a.mu.Lock()
	_, trusted := a.devices[pubB]
	priv := a.priv // snapshot: key reset swaps the pointer
	a.mu.Unlock()
	if !trusted {
		log.Printf("cmd from untrusted key -> dropped")
		return
	}
	var nonce [24]byte
	nb := unb64(str(m["nonce"]))
	if len(nb) != 24 {
		return
	}
	if a.seenNonce(str(m["nonce"])) {
		log.Printf("replayed nonce -> dropped")
		return
	}
	copy(nonce[:], nb)
	var peer [32]byte
	copy(peer[:], unb64(pubB))

	pt, ok := box.Open(nil, unb64(str(m["ct"])), &nonce, &peer, priv)
	if !ok {
		log.Printf("cmd decrypt failed -> dropped")
		return
	}
	var payload struct {
		Act string `json:"act"` // pause|resume|cancel
		ID  string `json:"id"`  // job id
		TS  int64  `json:"ts"`  // unix seconds (plugin >= v0.17), 0 for older
	}
	if err := json.Unmarshal(pt, &payload); err != nil || payload.ID == "" {
		log.Printf("cmd payload parse failed -> dropped")
		return
	}
	if !freshTS(payload.TS) {
		log.Printf("cmd with a stale timestamp -> dropped (replay?)")
		return
	}
	a.touchDevice(pubB)
	switch payload.Act {
	case "pause":
		a.pauseJob(payload.ID)
	case "resume":
		a.resumeJob(payload.ID)
	case "cancel":
		a.cancelJob(payload.ID)
	default:
		log.Printf("cmd %q unknown -> dropped", payload.Act)
	}
}

func (a *Agent) onJob(m map[string]any) {
	pubB := str(m["pub"])
	a.mu.Lock()
	_, trusted := a.devices[pubB]
	priv := a.priv // snapshot: key reset swaps the pointer
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
	if a.seenNonce(str(m["nonce"])) {
		log.Printf("replayed nonce -> dropped")
		return
	}
	copy(nonce[:], nb)
	var peer [32]byte
	copy(peer[:], unb64(pubB))

	pt, ok := box.Open(nil, unb64(str(m["ct"])), &nonce, &peer, priv)
	if !ok {
		log.Printf("job decrypt failed -> dropped")
		return
	}
	var payload struct {
		Magnet string `json:"magnet"`
		Cat    string `json:"cat"`
		Name   string `json:"name"`
		TS     int64  `json:"ts"` // unix seconds (plugin >= v0.17), 0 for older
	}
	if err := json.Unmarshal(pt, &payload); err != nil {
		log.Printf("job payload parse failed -> dropped")
		return
	}
	if !freshTS(payload.TS) {
		log.Printf("job with a stale timestamp -> dropped (replay?)")
		return
	}
	if !validMagnet(payload.Magnet) {
		log.Printf("job magnet rejected (not a magnet URI) -> dropped")
		return
	}
	dir, ok := categoryDir[payload.Cat]
	if !ok {
		dir = "Other" // unknown category never becomes raw path input
	}
	a.touchDevice(pubB)
	id := str(m["id"])
	go a.startDownload(id, payload.Magnet, dir, payload.Name)
}

// ---------- torrent engine ----------

// fileStorage uses plain file I/O with in-memory piece completion.
// This avoids the bbolt (.torrent.bolt.db) memory-mapping that panics on
// Windows ("CreateFileMapping ... externally altered"). Part files keep
// partial data on disk, so an interrupted job resumes after a restart
// (re-hashes what's there, continues from disk).
// pauseJob stops requesting data but keeps the torrent (and its files) around.
func (a *Agent) pauseJob(id string) {
	a.mu.Lock()
	j := a.jobs[id]
	a.mu.Unlock()
	if j == nil || j.t == nil || j.paused {
		return
	}
	func() { defer func() { _ = recover() }(); j.t.DisallowDataDownload() }()
	a.mu.Lock()
	j.paused = true
	j.state = "paused"
	j.speed = 0
	a.mu.Unlock()
	a.pushStatus()
	log.Printf("job %s paused: %q", id, j.name)
}

// resumeJob re-enables downloading for a paused job.
func (a *Agent) resumeJob(id string) {
	a.mu.Lock()
	j := a.jobs[id]
	a.mu.Unlock()
	if j == nil || j.t == nil || !j.paused {
		return
	}
	func() { defer func() { _ = recover() }(); j.t.AllowDataDownload() }()
	a.mu.Lock()
	j.paused = false
	j.state = "downloading"
	j.lastAt = time.Time{} // reset speed sampling
	a.mu.Unlock()
	a.pushStatus()
	log.Printf("job %s resumed: %q", id, j.name)
}

// cancelJob stops a download, removes it, and forgets it so it won't resume.
// cancelJob handles the ✕ action; the semantics depend on the job's state.
//
//   - done / seeding / error → DISMISS: remove from the list, files are NEVER
//     touched (seeding stops; error partials stay for manual cleanup);
//   - connecting / downloading / paused → CANCEL: signal the worker, wait for
//     it to exit, then apply the file policy (delete partials unless
//     KeepFilesOnCancel).
//
// Completed data cannot be deleted from here by design — only a file manager
// can do that.
func (a *Agent) cancelJob(id string) {
	a.mu.Lock()
	j := a.jobs[id]
	if j == nil {
		a.mu.Unlock()
		return
	}
	delete(a.jobs, id)
	state := j.state
	if !j.cancelled {
		j.cancelled = true
		if j.cancelCh != nil {
			close(j.cancelCh) // unblocks the metadata wait immediately
		}
	}
	keep := a.cfg.KeepFilesOnCancel
	base := filepath.Join(a.cfg.DownloadDir, j.dirOrEmpty())
	t := j.t
	a.mu.Unlock()

	active := state == "connecting" || state == "downloading" || state == "paused"

	// Collect file paths BEFORE dropping (needed only for the delete path).
	var files []string
	if active && !keep && t != nil {
		func() {
			defer func() { _ = recover() }()
			for _, f := range t.Files() {
				files = append(files, f.Path())
			}
		}()
	}
	if t != nil {
		func() { defer func() { _ = recover() }(); t.Drop() }()
	}

	if !active {
		log.Printf("job %s dismissed: %q (state %s, files untouched)", id, j.name, state)
		if j.magnet != "" {
			a.removePending(j.magnet)
		}
		a.pushStatus()
		return
	}

	// Wait for the worker goroutine to exit before touching files, so nothing
	// re-creates a .part behind our back mid-delete.
	if j.doneCh != nil {
		select {
		case <-j.doneCh:
		case <-time.After(3 * time.Second):
			log.Printf("job %s: worker did not exit within 3s, proceeding", id)
		}
	}

	if !keep {
		time.Sleep(300 * time.Millisecond) // let the engine release its handles
		removed := 0
		for _, rel := range files {
			rel = filepath.FromSlash(rel)
			// Try both layouts: <base>/<rel> and <base>/<basename(rel)>.
			cands := []string{
				filepath.Join(base, rel),
				filepath.Join(base, filepath.Base(rel)),
			}
			for _, p := range cands {
				for _, cand := range []string{p, p + ".part"} {
					if err := os.Remove(cand); err == nil {
						removed++
					}
				}
			}
		}
		// Remove now-empty directories left behind by the torrent.
		for _, rel := range files {
			d := filepath.Dir(filepath.Join(base, filepath.FromSlash(rel)))
			for len(d) > len(base) {
				if os.Remove(d) != nil {
					break // not empty (or gone) — stop climbing
				}
				d = filepath.Dir(d)
			}
		}
		log.Printf("job %s cancelled: %q (removed %d files)", id, j.name, removed)
	} else {
		log.Printf("job %s cancelled: %q (files kept)", id, j.name)
	}

	if j.magnet != "" {
		a.removePending(j.magnet)
	}
	a.pushStatus() // reflect the removal on the TV at once
}

// dirOrEmpty is nil-safe access to the job's category folder.
func (j *Job) dirOrEmpty() string {
	if j == nil {
		return ""
	}
	return j.dir
}

// setDir changes the download folder for future downloads. The folder must be
// creatable and writable, so the panel can report a real error instead of
// silently failing later, mid-download.
func (a *Agent) setDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("empty path")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	probe := filepath.Join(dir, ".lampa-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0644); err != nil {
		return err
	}
	os.Remove(probe)

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

// failJob marks a job as failed with a human-readable reason, visible in the
// panel and on the TV instead of a silent hang.
// failJob is the single exit for every failure path: it marks the job, drops
// the torrent from the engine (so an "error" never keeps downloading in the
// background) and removes the pending record (so a restart doesn't silently
// retry a job the user sees as failed). Partial files stay on disk.
func (a *Agent) failJob(j *Job, reason string) {
	a.mu.Lock()
	if j.cancelled { // cancel owns the cleanup; don't fight over the corpse
		a.mu.Unlock()
		return
	}
	j.state = "error"
	j.err = reason
	j.speed = 0
	t := j.t
	a.mu.Unlock()
	if t != nil {
		func() { defer func() { _ = recover() }(); t.Drop() }()
	}
	if j.magnet != "" {
		a.removePending(j.magnet)
	}
	a.pushStatus()
	log.Printf("job %s failed: %q — %s", j.id, j.name, reason)
}

func (a *Agent) startDownload(id, magnet, catDir, name string) {
	target := filepath.Join(a.cfg.DownloadDir, catDir)

	// Dedup: the same torrent sent twice (double-click on the remote, resend
	// after a hiccup) must not spawn a second competing job over the same files.
	ih := infoHash(magnet)
	a.mu.Lock()
	if ih != "" {
		for _, ex := range a.jobs {
			if ex.state != "error" && infoHash(ex.magnet) == ih {
				a.mu.Unlock()
				log.Printf("job %s duplicate of active %q -> skipped", id, ex.name)
				return
			}
		}
	}
	j := &Job{
		id: id, name: name, magnet: magnet, dir: catDir, state: "connecting",
		cancelCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
	a.jobs[id] = j
	a.mu.Unlock()
	defer close(j.doneCh) // cancelJob waits on this before touching files

	if err := os.MkdirAll(target, 0755); err != nil {
		a.failJob(j, dirErrRu(err))
		return
	}
	spec, err := torrent.TorrentSpecFromMagnetUri(magnet)
	if err != nil {
		a.failJob(j, "Некорректная ссылка")
		return
	}
	spec.Storage = fileStorage(target)

	t, _, err := a.tc.AddTorrentSpec(spec)
	if err != nil {
		a.failJob(j, "Не удалось добавить торрент")
		return
	}
	a.mu.Lock()
	j.t = t
	a.mu.Unlock()

	a.addPending(id, magnet, catDir, name) // persist so a restart resumes it, same ID
	log.Printf("job %s queued: %q -> %s", id, name, target)

	// Metadata (peer discovery) must arrive in reasonable time; otherwise the
	// job would sit on "connecting" forever with no explanation.
	select {
	case <-t.GotInfo():
	case <-j.cancelCh:
		return // cancelJob owns cleanup
	case <-time.After(5 * time.Minute):
		a.failJob(j, "Не найдены пиры — раздача недоступна")
		return
	}

	var total int64
	func() { defer func() { _ = recover() }(); total = t.Length() }()
	if free, err := freeSpace(target); err == nil && free > 0 && free < total {
		a.failJob(j, fmt.Sprintf("Недостаточно места: нужно %d ГиБ, свободно %d ГиБ",
			total/(1<<30)+1, free/(1<<30)))
		return
	}

	func() { defer func() { _ = recover() }(); t.DownloadAll() }()
	a.setState(j, "downloading")

	stalledSince := time.Time{}
	for {
		var done int64
		func() { defer func() { _ = recover() }(); done = t.BytesCompleted() }()
		pct := 0
		if total > 0 {
			pct = int(done * 100 / total)
		}
		now := time.Now()

		a.mu.Lock()
		if j.cancelled || j.state == "error" { // cancelled or failed elsewhere
			a.mu.Unlock()
			return
		}
		j.pct = pct
		// speed: exponentially smoothed bytes/sec between samples
		if !j.lastAt.IsZero() && !j.paused {
			if dt := now.Sub(j.lastAt).Seconds(); dt > 0 {
				inst := int64(float64(done-j.lastBytes) / dt)
				if inst < 0 {
					inst = 0
				}
				if j.speed == 0 {
					j.speed = inst
				} else {
					j.speed = (j.speed*2 + inst) / 3 // smooth out spikes
				}
			}
		}
		j.lastBytes, j.lastAt = done, now
		if !j.paused && j.state == "connecting" {
			j.state = "downloading"
		}
		paused := j.paused
		speed := j.speed
		a.mu.Unlock()

		if done >= total && total > 0 {
			break
		}

		// Stall detection: no data and no peers for a long time means the swarm
		// is dead — say so instead of spinning at 0% forever.
		if !paused && speed == 0 {
			peers := 0
			func() {
				defer func() { _ = recover() }()
				peers = t.Stats().ActivePeers
			}()
			if peers == 0 {
				if stalledSince.IsZero() {
					stalledSince = now
				} else if now.Sub(stalledSince) > 10*time.Minute {
					a.failJob(j, "Нет пиров — загрузка остановилась")
					return
				}
			} else {
				stalledSince = time.Time{}
			}
		} else {
			stalledSince = time.Time{}
		}

		time.Sleep(1 * time.Second)
	}

	a.mu.Lock()
	j.speed = 0
	a.mu.Unlock()

	a.removePending(magnet) // done downloading; no longer needs resume
	a.addHistory(HistEntry{Name: name, Dir: catDir, MiB: total / (1 << 20), Done: time.Now().Unix()})
	if a.cfg.KeepSeeding {
		a.setState(j, "seeding")
		log.Printf("job %s complete: %q (seeding)", id, name)
	} else {
		t.Drop() // stops seeding; files stay on disk
		a.setState(j, "done")
		log.Printf("job %s complete: %q (stopped)", id, name)
	}
}

// addHistory persists a completed download (newest last, capped), so the list
// survives agent restarts.
func (a *Agent) addHistory(h HistEntry) {
	a.mu.Lock()
	a.cfg.History = append(a.cfg.History, h)
	if len(a.cfg.History) > historyCap {
		a.cfg.History = a.cfg.History[len(a.cfg.History)-historyCap:]
	}
	a.mu.Unlock()
	a.saveConfig()
}

// clearHistory wipes the completed-downloads list (files are untouched).
func (a *Agent) clearHistory() {
	a.mu.Lock()
	a.cfg.History = nil
	a.mu.Unlock()
	a.saveConfig()
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

// pushStatus sends the current job list to the relay right away, so the plugin
// sees pause/cancel results immediately instead of waiting for the next tick.
func (a *Agent) pushStatus() {
	a.mu.Lock()
	jobs := make([]map[string]any, 0, len(a.jobs))
	for _, j := range a.jobs {
		jobs = append(jobs, map[string]any{
			"id": j.id, "pct": j.pct, "state": j.state, "paused": j.paused,
			"speed": j.speed, "err": j.err,
		})
	}
	a.mu.Unlock()
	a.send(map[string]any{"type": "status", "jobs": jobs})
}

func (a *Agent) statusLoop() {
	for range time.Tick(2 * time.Second) {
		a.mu.Lock()
		jobs := make([]map[string]any, 0, len(a.jobs))
		for _, j := range a.jobs {
			var total, done int64
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
			eta := int64(-1)
			if j.speed > 0 && total > done {
				eta = (total - done) / j.speed
			}
			jobs = append(jobs, map[string]any{
				"id": j.id, "pct": j.pct, "state": j.state,
				"speed": j.speed, "eta": eta,
				"peers": peers, "seeds": seeds, "paused": j.paused,
				"err": j.err,
			})
		}
		a.mu.Unlock()
		a.send(map[string]any{"type": "status", "jobs": jobs}) // send even when empty: clears finished/cancelled jobs on the TV
	}
}

// ---------- main ----------

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Native panel window mode: no engine, no re-exec — just the webview.
	for _, a := range os.Args[1:] {
		if len(a) > 9 && a[:9] == "--window=" {
			runWindow(a[9:])
			return
		}
		if a == "--version" || a == "-version" {
			fmt.Println("Lampa Downloader agent", version)
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
	logPath := setupLogging(*cfgPath)
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
		logPath: logPath,
		started: time.Now(),
		cfg:     cfg,
		priv:    &priv,
		pub:     &pub,
		code:    deriveCode(pub[:]),
		jobs:    make(map[string]*Job),
		devices: make(map[string]*Device),
		outCh:   make(chan map[string]any, 32),
	}
	for i := range cfg.Devices {
		d := cfg.Devices[i]
		a.devices[d.Pub] = &d
	}
	a.saveConfig() // persist freshly-generated keys / migrated legacy fields

	// First run (nothing paired yet): open the pairing window automatically so
	// the very first TV connects without hunting for the panel button.
	if len(a.devices) == 0 {
		a.openPairWindow(pairFirstRunDur)
	}

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
	fmt.Printf("  Lampa Downloader agent %s\n", version)
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

	// apply the autostart preference from config (default: on for desktop)
	if err := setAutostart(a.cfg.Autostart); err != nil {
		log.Printf("autostart: %v", err)
	}
	if *uiToken == "" { // env is preferable: tokens in process args leak via ps
		*uiToken = os.Getenv("UI_TOKEN")
	}
	if !loopbackBind(uiAddr) && *uiToken == "" {
		log.Fatalf("панель на внешнем адресе (%s) требует токен: задайте -ui-token или переменную окружения UI_TOKEN", uiAddr)
	}
	a.uiToken = *uiToken
	a.startUI(uiAddr)

	// resume downloads that were still active when we last exited
	a.mu.Lock()
	resume := append([]PendingJob(nil), a.cfg.Pending...)
	a.mu.Unlock()
	for _, p := range resume {
		id := p.ID
		if id == "" { // pending record saved by <= v1.0.7
			id = randID()
		}
		log.Printf("resuming: %q", p.Name)
		go a.startDownload(id, p.Magnet, p.Dir, p.Name)
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
		if !validMagnet(arg) {
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
