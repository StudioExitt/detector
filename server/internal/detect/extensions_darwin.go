package detect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"detector/internal/config"
)

// extensionsDetector inventories browser extensions on macOS and scores each
// one for malicious behaviour (see extrisk.go). Chromium browsers are read
// from every profile's Secure Preferences / Preferences, which also covers
// unpacked and --load-extension installs that live outside the Extensions
// folder; Firefox from extensions.json. Policy force-installs and
// "External Extensions" sideloading are reported as well.
type extensionsDetector struct {
	trusted map[string]bool
	blocked map[string]bool
	cfg     config.ExtensionsDetectConfig
	// replaceable in tests
	scan    func(context.Context) []browserExt
	sources func(context.Context) []extSource
}

func newExtensionsDetector(cfg config.ExtensionsDetectConfig) Detector {
	d := &extensionsDetector{cfg: cfg, trusted: map[string]bool{}, blocked: map[string]bool{},
		scan: scanBrowserExtensions, sources: scanExtensionSources}
	for _, id := range cfg.TrustedIDs {
		d.trusted[id] = true
	}
	for _, id := range cfg.BlockedIDs {
		d.blocked[id] = true
	}
	return d
}

func (d *extensionsDetector) Name() string { return "extensions" }

type browserExt struct {
	Browser  string
	Profile  string
	ID       string
	Name     string
	Version  string
	Dir      string
	Manifest extManifest
	Install  extInstall
	Perms    []string
	AllSites bool
	Enabled  bool
	Risk     extRisk
}

func (e browserExt) key() string   { return e.Browser + "|" + e.Profile + "|" + e.ID }
func (e browserExt) label() string { return fmt.Sprintf("%s[%s] %s", e.Browser, e.Profile, e.Name) }

// chromium-family browsers under ~/Library/Application Support
var chromiumBrowsers = []struct{ name, dir, bundleID string }{
	{"Chrome", "Google/Chrome", "com.google.Chrome"},
	{"Chrome Beta", "Google/Chrome Beta", "com.google.Chrome.beta"},
	{"Chromium", "Chromium", "org.chromium.Chromium"},
	{"Edge", "Microsoft Edge", "com.microsoft.Edge"},
	{"Brave", "BraveSoftware/Brave-Browser", "com.brave.Browser"},
	{"Arc", "Arc/User Data", "company.thebrowser.Browser"},
	{"Vivaldi", "Vivaldi", "com.vivaldi.Vivaldi"},
	{"Whale", "Naver/Whale", "com.naver.Whale"},
	{"Opera", "com.operasoftware.Opera", "com.operasoftware.Opera"},
}

type extState struct {
	Version string   `json:"v"`
	Score   int      `json:"s"`
	Perms   []string `json:"p"`
	Codes   []string `json:"c"`
}

// reason codes that mean "the browser vendor or the code itself says this is bad"
func isVerdictCode(c string) bool {
	return strings.HasPrefix(c, "chrome_") || strings.HasPrefix(c, "code_") ||
		c == "cws_violation" || c == "cws_removed" || c == "loc_command_line"
}

func (d *extensionsDetector) Check(ctx context.Context, env *Env) (Report, error) {
	blocked := d.loadBlocklist()
	exts := d.scan(ctx)
	sources := d.sources(ctx)

	var known map[string]extState
	found, err := env.State.Load(ctx, "inventory", &known)
	if err != nil {
		return Report{}, err
	}
	knownSources := map[string]bool{}
	if _, err := env.State.Load(ctx, "sources", &knownSources); err != nil {
		return Report{}, err
	}

	var findings []Finding
	next := map[string]extState{}
	counts := map[string]int{}
	for i := range exts {
		e := &exts[i]
		st := extState{Version: e.Version, Score: e.Risk.Score, Perms: e.Perms, Codes: e.Risk.codes()}
		next[e.key()] = st
		counts[e.Risk.Level]++

		if d.trusted[e.ID] {
			continue
		}
		top := e.Risk.summary(4)
		where := fmt.Sprintf("%s v%s [%s, %s]", e.label(), e.Version, e.ID, locationText(e.Install.Location))

		if blocked[e.ID] {
			findings = append(findings, Finding{
				Rule: "browser.ext_blocklisted", Category: CategoryIntrusion, Severity: SevCritical, Source: e.label(), Key: e.key(),
				Message: "차단 목록에 있는 확장이 설치됨: " + where,
			})
		}

		prev, seen := known[e.key()]
		verdictCodes := slices.DeleteFunc(slices.Clone(st.Codes), func(c string) bool { return !isVerdictCode(c) })
		category := CategoryVulnScan
		if len(verdictCodes) > 0 {
			category = CategoryIntrusion
		}

		switch {
		case !found:
			// baseline: report extensions that are already risky, once
			if e.Risk.Level == SevHigh || e.Risk.Level == SevCritical {
				findings = append(findings, Finding{
					Rule: "browser.ext_risky", Category: category, Severity: e.Risk.Level, Source: e.label(), Key: e.key(),
					Message: fmt.Sprintf("위험도 높은 브라우저 확장 (점수 %d): %s — %s", e.Risk.Score, where, top),
				})
			}
		case !seen:
			findings = append(findings, Finding{
				Rule: "browser.ext_new", Category: CategoryIntrusion, Severity: e.Risk.Level, Source: e.label(), Key: e.key(),
				Message: fmt.Sprintf("새 브라우저 확장 설치 (위험도 %d, %s): %s — %s", e.Risk.Score, e.Risk.Level, where, orNone(top)),
			})
		default:
			added := diff(st.Perms, prev.Perms)
			newVerdicts := diff(verdictCodes, prev.Codes)
			if prev.Version != e.Version && len(added) > 0 {
				findings = append(findings, Finding{
					Rule: "browser.ext_perm_escalation", Category: CategoryIntrusion, Severity: SevHigh, Source: e.label(), Key: e.key() + "|" + e.Version,
					Message: fmt.Sprintf("업데이트(v%s → v%s) 후 권한 확대: %s — %s (개발자 계정 탈취·공급망 공격 시 흔한 패턴)",
						prev.Version, e.Version, strings.Join(added, ", "), where),
				})
			}
			if len(newVerdicts) > 0 {
				sev := SevHigh
				if e.Risk.Level == SevCritical {
					sev = SevCritical
				}
				what := "새 위험 신호"
				if prev.Version != e.Version {
					what = fmt.Sprintf("업데이트(v%s → v%s) 후 새 위험 신호", prev.Version, e.Version)
				}
				findings = append(findings, Finding{
					Rule: "browser.ext_new_verdict", Category: CategoryIntrusion, Severity: sev, Source: e.label(), Key: e.key() + "|" + strings.Join(newVerdicts, ","),
					Message: fmt.Sprintf("%s: %s — %s", what, where, reasonsFor(e.Risk, newVerdicts)),
				})
			}
		}
	}

	for _, s := range sources {
		if knownSources[s.Key] {
			continue
		}
		knownSources[s.Key] = true
		findings = append(findings, Finding{
			Rule: s.Rule, Category: CategoryIntrusion, Severity: s.Severity, Source: s.Browser, Key: s.Key, Message: s.Message,
		})
	}

	if err := env.State.Save(ctx, "inventory", next); err != nil {
		return Report{}, err
	}
	if err := env.State.Save(ctx, "sources", knownSources); err != nil {
		return Report{}, err
	}

	summary := fmt.Sprintf("브라우저 확장 %d개 — 위험 %d · 높음 %d · 주의 %d · 낮음 %d, 강제설치/사이드로드 %d건",
		len(exts), counts[SevCritical], counts[SevHigh], counts[SevMedium], counts[SevLow], len(sources))
	if !found {
		summary = "기준선 생성: " + summary
	}
	return Report{Findings: findings, Summary: summary, Checks: d.checks(exts, sources)}, nil
}

func (d *extensionsDetector) checks(exts []browserExt, sources []extSource) []Check {
	browsers := map[string]int{}
	for _, e := range exts {
		browsers[e.Browser]++
	}
	var parts []string
	for _, b := range sortedKeys(browsers) {
		parts = append(parts, fmt.Sprintf("%s %d", b, browsers[b]))
	}
	checks := []Check{{Name: "browsers", Status: CheckOK, Detail: orNone(strings.Join(parts, ", "))}}
	for _, s := range sources {
		checks = append(checks, Check{Name: s.Browser + " " + s.Kind, Status: CheckWarn, Detail: s.Message})
	}

	sorted := slices.Clone(exts)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Risk.Score > sorted[j].Risk.Score })
	for _, e := range sorted {
		st := CheckOK
		switch e.Risk.Level {
		case SevCritical, SevHigh:
			st = CheckFail
		case SevMedium:
			st = CheckWarn
		}
		state := "활성"
		if !e.Enabled {
			state = "비활성(" + orNone(disableReasonText(e.Install.DisableReasons)) + ")"
		}
		note := ""
		if d.trusted[e.ID] {
			st, note = CheckOK, " · 신뢰 목록"
		}
		checks = append(checks, Check{
			Name:   fmt.Sprintf("%s v%s", e.label(), e.Version),
			Status: st,
			Detail: fmt.Sprintf("위험도 %d (%s; 악성 징후 %d + 권한 %d÷3) · %s · %s%s · %s — %s",
				e.Risk.Score, e.Risk.Level, e.Risk.Signal, e.Risk.Capability, locationText(e.Install.Location), state, note, e.ID, orNone(e.Risk.summary(5))),
		})
	}
	return checks
}

func (d *extensionsDetector) loadBlocklist() map[string]bool {
	out := map[string]bool{}
	for id := range d.blocked {
		out[id] = true
	}
	if d.cfg.BlocklistFile == "" {
		return out
	}
	f, err := os.Open(d.cfg.BlocklistFile)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out[strings.Fields(line)[0]] = true
		}
	}
	return out
}

// ---------------------------------------------------------------- inventory

func userHomes() []string {
	homes, _ := filepath.Glob("/Users/*")
	return slices.DeleteFunc(homes, func(h string) bool { return filepath.Base(h) == "Shared" })
}

func scanBrowserExtensions(ctx context.Context) []browserExt {
	var out []browserExt
	for _, home := range userHomes() {
		support := filepath.Join(home, "Library/Application Support")
		for _, b := range chromiumBrowsers {
			if ctx.Err() != nil {
				return out
			}
			out = append(out, scanChromium(b.name, filepath.Join(support, b.dir))...)
		}
		out = append(out, scanFirefox(filepath.Join(support, "Firefox/Profiles"))...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

type prefExt struct {
	Location       *int           `json:"location"`
	FromWebstore   *bool          `json:"from_webstore"`
	Path           string         `json:"path"`
	Manifest       map[string]any `json:"manifest"`
	CWS            *cwsInfo       `json:"cws-info"`
	BlacklistState int            `json:"blacklist_state"`
	BlocklistState int            `json:"blocklist_state"`
	DisableReasons any            `json:"disable_reasons"` // []int (new) or int bitmask (old)
	State          *int           `json:"state"`           // old: 0 disabled, 1 enabled
}

func readPrefExtensions(path string) map[string]prefExt {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var p struct {
		Extensions struct {
			Settings map[string]prefExt `json:"settings"`
		} `json:"extensions"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	return p.Extensions.Settings
}

func scanChromium(browser, base string) []browserExt {
	prefFiles, _ := filepath.Glob(filepath.Join(base, "*", "Preferences"))
	var out []browserExt
	for _, prefFile := range prefFiles {
		profDir := filepath.Dir(prefFile)
		profile := filepath.Base(profDir)
		if profile == "System Profile" || profile == "Guest Profile" {
			continue
		}
		settings := readPrefExtensions(prefFile)
		if settings == nil {
			settings = map[string]prefExt{}
		}
		for id, v := range readPrefExtensions(filepath.Join(profDir, "Secure Preferences")) {
			settings[id] = v // Secure Preferences wins
		}
		for id, v := range settings {
			if e, ok := chromiumExt(browser, profile, profDir, id, v); ok {
				out = append(out, e)
			}
		}
	}
	return out
}

func chromiumExt(browser, profile, profDir, id string, v prefExt) (browserExt, bool) {
	loc := 0
	if v.Location != nil {
		loc = *v.Location
	}
	if isComponentLocation(loc) || (v.Manifest == nil && v.Path == "") {
		return browserExt{}, false
	}
	dir := v.Path
	if dir != "" && !filepath.IsAbs(dir) {
		dir = filepath.Join(profDir, "Extensions", dir)
	}
	var mf extManifest
	if raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err != nil || json.Unmarshal(raw, &mf) != nil {
		// files missing: fall back to the manifest copy kept in preferences
		if v.Manifest == nil {
			return browserExt{}, false
		}
		raw, _ := json.Marshal(v.Manifest)
		mf = extManifest{}
		_ = json.Unmarshal(raw, &mf)
		dir = ""
	}
	if mf.Name == "" {
		return browserExt{}, false
	}

	inst := extInstall{Location: loc, FromWebstore: v.FromWebstore, CWS: v.CWS, BlocklistState: max(v.BlacklistState, v.BlocklistState)}
	inst.DisableReasons = parseDisableReasons(v.DisableReasons)
	e := browserExt{
		Browser: browser, Profile: profile, ID: id, Name: mf.Name, Version: mf.Version, Dir: dir, Manifest: mf, Install: inst,
		Enabled: len(inst.DisableReasons) == 0 && (v.State == nil || *v.State != 0),
	}
	var code []riskReason
	if dir != "" {
		e.Name = localizedName(dir, mf.Name, mf.DefaultLocale)
		code = scanExtCodeCached(dir, id)
	}
	e.Perms, e.AllSites = manifestPerms(&mf)
	e.Risk = assessExtension(&mf, inst, code)
	return e, true
}

// Extension code only changes with a new version directory, so scan results
// are cached by directory and manifest modification time.
var extCodeCache sync.Map // dir -> cachedCodeScan

type cachedCodeScan struct {
	mod  time.Time
	hits []riskReason
}

func scanExtCodeCached(dir, id string) []riskReason {
	fi, err := os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return scanExtCode(dir, id)
	}
	if c, ok := extCodeCache.Load(dir); ok && c.(cachedCodeScan).mod.Equal(fi.ModTime()) {
		return c.(cachedCodeScan).hits
	}
	hits := scanExtCode(dir, id)
	extCodeCache.Store(dir, cachedCodeScan{mod: fi.ModTime(), hits: hits})
	return hits
}

func parseDisableReasons(v any) []int {
	switch x := v.(type) {
	case float64:
		if x != 0 {
			return []int{int(x)}
		}
	case []any:
		var out []int
		for _, r := range x {
			if f, ok := r.(float64); ok && f != 0 {
				out = append(out, int(f))
			}
		}
		return out
	}
	return nil
}

func locationText(l int) string {
	switch l {
	case locInternal:
		return "일반 설치"
	case locExternalPref, locExternalRegistry, locExtPrefDownload:
		return "외부 설치"
	case locUnpacked:
		return "압축해제(개발자 모드)"
	case locCommandLine:
		return "명령줄 --load-extension"
	case locExternalPolicy, locExtPolicyDownload:
		return "정책 강제 설치"
	}
	return "설치 경로 미상"
}

// localizedName resolves "__MSG_appName__" via _locales/<locale>/messages.json.
func localizedName(dir, name, locale string) string {
	key, ok := strings.CutPrefix(name, "__MSG_")
	if !ok {
		return name
	}
	key = strings.TrimSuffix(key, "__")
	for _, loc := range []string{"ko", locale, "en", "en_US"} {
		if loc == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &msgs) != nil {
			continue
		}
		for k, v := range msgs {
			if strings.EqualFold(k, key) && v.Message != "" {
				return v.Message
			}
		}
	}
	return name
}

type firefoxAddons struct {
	Addons []struct {
		ID              string                `json:"id"`
		Version         string                `json:"version"`
		Type            string                `json:"type"`
		Location        string                `json:"location"`
		Active          bool                  `json:"active"`
		DefaultLocale   struct{ Name string } `json:"defaultLocale"`
		UserPermissions *struct {
			Permissions []string `json:"permissions"`
			Origins     []string `json:"origins"`
		} `json:"userPermissions"`
	} `json:"addons"`
}

func scanFirefox(profiles string) []browserExt {
	files, _ := filepath.Glob(filepath.Join(profiles, "*", "extensions.json"))
	var out []browserExt
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var fa firefoxAddons
		if json.Unmarshal(raw, &fa) != nil {
			continue
		}
		for _, a := range fa.Addons {
			if a.Type != "extension" || strings.HasPrefix(a.Location, "app-") {
				continue
			}
			var mf extManifest
			mf.Name, mf.Version = a.DefaultLocale.Name, a.Version
			if a.UserPermissions != nil {
				for _, p := range a.UserPermissions.Permissions {
					mf.Permissions = append(mf.Permissions, p)
				}
				for _, o := range a.UserPermissions.Origins {
					mf.HostPermissions = append(mf.HostPermissions, o)
				}
			}
			e := browserExt{Browser: "Firefox", Profile: filepath.Base(filepath.Dir(f)), ID: a.ID, Name: mf.Name, Version: a.Version, Manifest: mf, Enabled: a.Active}
			e.Perms, e.AllSites = manifestPerms(&mf)
			e.Risk = assessExtension(&mf, extInstall{}, nil)
			out = append(out, e)
		}
	}
	return out
}

// ------------------------------------------------- force-install / sideload

type extSource struct {
	Key      string
	Browser  string
	Kind     string
	Rule     string
	Severity string
	Message  string
}

// scanExtensionSources finds extensions pushed into browsers from outside:
// managed policies (MDM or a malicious configuration profile installing
// ExtensionInstallForcelist) and "External Extensions" JSON files that
// adware installers drop.
func scanExtensionSources(ctx context.Context) []extSource {
	var out []extSource
	for _, b := range chromiumBrowsers {
		plists, _ := filepath.Glob("/Library/Managed Preferences/" + b.bundleID + ".plist")
		userPlists, _ := filepath.Glob("/Library/Managed Preferences/*/" + b.bundleID + ".plist")
		for _, p := range append(plists, userPlists...) {
			out = append(out, policyForceInstalls(ctx, b.name, p)...)
		}

		dirs := []string{filepath.Join("/Library/Application Support", b.dir, "External Extensions")}
		for _, h := range userHomes() {
			dirs = append(dirs, filepath.Join(h, "Library/Application Support", b.dir, "External Extensions"))
		}
		for _, dir := range dirs {
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			for _, f := range files {
				out = append(out, externalExtension(b.name, f))
			}
		}
	}
	return out
}

func externalExtension(browser, f string) extSource {
	var ext struct {
		UpdateURL string `json:"external_update_url"`
		CRX       string `json:"external_crx"`
	}
	if raw, err := os.ReadFile(f); err == nil {
		_ = json.Unmarshal(raw, &ext)
	}
	id := strings.TrimSuffix(filepath.Base(f), ".json")
	sev, how := SevMedium, "웹스토어 업데이트 URL"
	switch {
	case ext.CRX != "":
		sev, how = SevHigh, "로컬 CRX 파일 "+ext.CRX
	case ext.UpdateURL != "" && !trustedUpdateURL(ext.UpdateURL):
		sev, how = SevHigh, "자체 업데이트 서버 "+ext.UpdateURL
	}
	return extSource{
		Key: "external|" + f, Browser: browser, Kind: "External Extensions", Rule: "browser.ext_sideload", Severity: sev,
		Message: fmt.Sprintf("외부 프로그램의 확장 사이드로드 설정: %s (%s) — %s", id, how, f),
	}
}

func policyForceInstalls(ctx context.Context, browser, plist string) []extSource {
	raw, err := runCmd(ctx, 10*time.Second, "plutil", "-convert", "json", "-o", "-", plist)
	if err != nil {
		return nil
	}
	var pol struct {
		Forcelist []string                  `json:"ExtensionInstallForcelist"`
		Settings  map[string]map[string]any `json:"ExtensionSettings"`
	}
	if json.Unmarshal([]byte(raw), &pol) != nil {
		return nil
	}
	var out []extSource
	addEntry := func(id, url string) {
		sev, how := SevMedium, "웹스토어"
		if url != "" && !trustedUpdateURL(url) {
			sev, how = SevHigh, "자체 업데이트 서버 "+url
		}
		out = append(out, extSource{
			Key: "policy|" + plist + "|" + id, Browser: browser, Kind: "policy force-install", Rule: "browser.ext_policy_install", Severity: sev,
			Message: fmt.Sprintf("정책으로 강제 설치되는 확장: %s (%s) — %s. 회사 MDM 이 아니라면 악성 구성 프로파일 의심", id, how, plist),
		})
	}
	for _, entry := range pol.Forcelist {
		id, url, _ := strings.Cut(entry, ";")
		addEntry(strings.TrimSpace(id), strings.TrimSpace(url))
	}
	for id, s := range pol.Settings {
		if mode, _ := s["installation_mode"].(string); mode == "force_installed" || mode == "normal_installed" {
			url, _ := s["update_url"].(string)
			addEntry(id, url)
		}
	}
	return out
}

// ------------------------------------------------------------------ helpers

func diff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func reasonsFor(r extRisk, codes []string) string {
	var parts []string
	for _, x := range r.Reasons {
		if slices.Contains(codes, x.Code) {
			parts = append(parts, x.Text)
		}
	}
	return strings.Join(parts, "; ")
}
