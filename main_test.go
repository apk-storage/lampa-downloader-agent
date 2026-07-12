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

// cryptoRand adapts crypto/rand for box.GenerateKey in tests.
type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }
