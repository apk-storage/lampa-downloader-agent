package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// deriveCode must stay byte-compatible with the JS plugin (same key -> same code).
// The vector below was cross-checked against the browser implementation.
func TestDeriveCodeMatchesPlugin(t *testing.T) {
	pub, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := deriveCode(pub), "772526"; got != want {
		t.Fatalf("deriveCode = %q, want %q (plugin and agent must agree)", got, want)
	}
}

func TestDeriveCodeIsSixDigits(t *testing.T) {
	for i := 0; i < 200; i++ {
		pub, _, err := box.GenerateKey(cryptoRand{})
		if err != nil {
			t.Fatal(err)
		}
		code := deriveCode(pub[:])
		if len(code) != 6 {
			t.Fatalf("code %q: want 6 chars", code)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatalf("code %q: must be digits only", code)
			}
		}
	}
}

// End-to-end sanity: what the plugin seals, the agent must open.
func TestSealOpenRoundTrip(t *testing.T) {
	pubA, privA, _ := box.GenerateKey(cryptoRand{}) // plugin
	pubB, privB, _ := box.GenerateKey(cryptoRand{}) // agent

	msg := []byte(`{"magnet":"magnet:?xt=urn:btih:` + strings.Repeat("a", 40) + `"}`)
	var nonce [24]byte
	copy(nonce[:], "0123456789abcdefghijklmn")

	sealed := box.Seal(nil, msg, &nonce, pubB, privA)
	opened, ok := box.Open(nil, sealed, &nonce, pubA, privB)
	if !ok {
		t.Fatal("agent could not open what the plugin sealed")
	}
	if string(opened) != string(msg) {
		t.Fatalf("round trip mismatch: %q != %q", opened, msg)
	}
}

func TestB64RoundTrip(t *testing.T) {
	in := []byte{0, 1, 2, 250, 251, 255}
	if got := unb64(b64(in)); string(got) != string(in) {
		t.Fatalf("b64 round trip failed: %v != %v", got, in)
	}
}

func TestMagnetValidation(t *testing.T) {
	valid := []string{
		"magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
		"magnet:?xt=urn:btih:0123456789ABCDEF0123456789abcdef01234567&dn=Film",
	}
	invalid := []string{
		"",
		"http://example.com/file.torrent",
		"magnet:?xt=urn:btih:tooshort",
		"magnet:?xt=urn:sha1:0123456789abcdef0123456789abcdef01234567",
		"; rm -rf /",
	}
	for _, m := range valid {
		if !magnetRe.MatchString(m) {
			t.Errorf("valid magnet rejected: %q", m)
		}
	}
	for _, m := range invalid {
		if magnetRe.MatchString(m) {
			t.Errorf("invalid magnet accepted: %q", m)
		}
	}
}

// Unknown categories must never become raw path input (path traversal guard).
func TestCategoryWhitelist(t *testing.T) {
	if categoryDir["movies"] != "Movies" || categoryDir["shows"] != "Shows" {
		t.Fatal("known categories changed unexpectedly")
	}
	for _, evil := range []string{"../../etc", "C:\\Windows", "", "unknown"} {
		if _, ok := categoryDir[evil]; ok {
			t.Errorf("category %q must not be in the whitelist", evil)
		}
	}
}

func TestFmtCode(t *testing.T) {
	if got := fmtCode("772526"); got != "772 526" {
		t.Fatalf("fmtCode = %q, want %q", got, "772 526")
	}
	if got := fmtCode("odd"); got != "odd" {
		t.Fatalf("fmtCode should pass through non-6-digit input, got %q", got)
	}
}

func TestConfigInitAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")

	cfg, err := loadOrInitConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Priv == "" || cfg.Pub == "" {
		t.Fatal("fresh config must contain generated keys")
	}
	if cfg.DownloadDir == "" {
		t.Fatal("fresh config must have a download dir")
	}

	// Reload: keys must be stable, otherwise the pairing code would change.
	again, err := loadOrInitConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Pub != cfg.Pub || again.Priv != cfg.Priv {
		t.Fatal("keys must persist across restarts (pairing code depends on them)")
	}
}

func TestPendingAddRemove(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfgPath: filepath.Join(dir, "agent.json")}

	a.addPending("magnet:?xt=urn:btih:aaa", "Movies", "Film")
	a.addPending("magnet:?xt=urn:btih:aaa", "Movies", "Film") // duplicate
	if len(a.cfg.Pending) != 1 {
		t.Fatalf("duplicate pending job stored: %d entries", len(a.cfg.Pending))
	}

	a.addPending("magnet:?xt=urn:btih:bbb", "Shows", "Series")
	if len(a.cfg.Pending) != 2 {
		t.Fatalf("want 2 pending jobs, got %d", len(a.cfg.Pending))
	}

	a.removePending("magnet:?xt=urn:btih:aaa")
	if len(a.cfg.Pending) != 1 || a.cfg.Pending[0].Name != "Series" {
		t.Fatalf("removePending removed the wrong job: %+v", a.cfg.Pending)
	}
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	w := newRotWriter(path, 128) // tiny limit to force a rotation

	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte("0123456789abcdef\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current log missing: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated log missing: %v", err)
	}
	st, _ := os.Stat(path)
	if st.Size() > 128 {
		t.Fatalf("current log exceeded the limit: %d bytes", st.Size())
	}
}

// A corrupt config must never brick the agent: it gets backed up next to the
// original and a fresh one is generated.
func TestConfigBrokenBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOrInitConfig(path)
	if err != nil {
		t.Fatalf("broken config must re-init, not fail: %v", err)
	}
	if cfg.Priv == "" || cfg.Pub == "" {
		t.Fatal("re-initialized config must contain fresh keys")
	}
	ents, _ := os.ReadDir(dir)
	found := false
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "agent.json.broken-") {
			found = true
		}
	}
	if !found {
		t.Fatal("broken config was not backed up")
	}
}

// Valid JSON with corrupt keys is a broken identity — same treatment.
func TestConfigBadKeysBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	os.WriteFile(path, []byte(`{"priv":"short","pub":"short"}`), 0600)

	cfg, err := loadOrInitConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(unb64(cfg.Priv)) != 32 || len(unb64(cfg.Pub)) != 32 {
		t.Fatal("keys must be regenerated when corrupt")
	}
}

// Legacy "trusted" keys (<= v1.0.6) must migrate into named Devices.
func TestConfigMigratesLegacyTrusted(t *testing.T) {
	pub, _, _ := box.GenerateKey(cryptoRand{})
	plug, _, _ := box.GenerateKey(cryptoRand{})
	c := Config{Priv: b64(pub[:]), Pub: b64(pub[:]), Trusted: []string{b64(plug[:])}}
	normalizeConfig(&c)
	if len(c.Devices) != 1 {
		t.Fatalf("want 1 migrated device, got %d", len(c.Devices))
	}
	if c.Devices[0].Pub != b64(plug[:]) || c.Devices[0].Name == "" {
		t.Fatalf("bad migrated device: %+v", c.Devices[0])
	}
	if c.Trusted != nil {
		t.Fatal("legacy trusted list must be cleared after migration")
	}
	// second pass must not duplicate
	c.Trusted = []string{b64(plug[:])}
	normalizeConfig(&c)
	if len(c.Devices) != 1 {
		t.Fatalf("migration duplicated a device: %d", len(c.Devices))
	}
}

func TestInfoHash(t *testing.T) {
	hexA := "magnet:?xt=urn:btih:0123456789ABCDEF0123456789abcdef01234567&dn=Film"
	hexB := "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&tr=udp://x"
	if infoHash(hexA) != infoHash(hexB) || infoHash(hexA) == "" {
		t.Fatal("same torrent with different trackers/case must match")
	}
	if infoHash("not a magnet") != "" {
		t.Fatal("no infohash must return empty string")
	}
	b32 := "magnet:?xt=urn:btih:MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"
	if infoHash(b32) == "" {
		t.Fatal("base32 infohash must be recognized")
	}
}

func TestHistoryCap(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfgPath: filepath.Join(dir, "agent.json"), devices: map[string]*Device{}}
	for i := 0; i < historyCap+10; i++ {
		a.addHistory(HistEntry{Name: "x", MiB: int64(i)})
	}
	if len(a.cfg.History) != historyCap {
		t.Fatalf("history not capped: %d", len(a.cfg.History))
	}
	if a.cfg.History[len(a.cfg.History)-1].MiB != int64(historyCap+9) {
		t.Fatal("cap must drop the oldest entries, not the newest")
	}
}

func TestRenameRevokeDevice(t *testing.T) {
	dir := t.TempDir()
	plug, _, _ := box.GenerateKey(cryptoRand{})
	pubB := b64(plug[:])
	a := &Agent{cfgPath: filepath.Join(dir, "agent.json"), devices: map[string]*Device{}}
	a.onPaired(pubB)
	if len(a.devices) != 1 {
		t.Fatal("pairing did not add a device")
	}
	if err := a.renameDevice(pubB, "Гостиная"); err != nil {
		t.Fatal(err)
	}
	if a.devices[pubB].Name != "Гостиная" {
		t.Fatal("rename did not stick")
	}
	if err := a.renameDevice(pubB, strings.Repeat("я", 41)); err == nil {
		t.Fatal("41-rune name must be rejected")
	}
	a.revokeDevice(pubB)
	if len(a.devices) != 0 {
		t.Fatal("revoke did not remove the device")
	}
}

// cryptoRand adapts crypto/rand for box.GenerateKey in tests.
type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }
