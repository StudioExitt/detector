package detect

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Browser extension risk scoring. Signals come from three places:
//   - the manifest (permissions, host access, overrides, update URL, CSP)
//   - how Chrome installed / judged it (Secure Preferences: location,
//     from_webstore, cws-info, blocklist state, disable reasons)
//   - the extension's own JavaScript (stealer / clipper / keylogger patterns)
//
// Points add up to a score; level thresholds are in riskLevel.

// extManifest is the subset of manifest.json used for scoring.
type extManifest struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ManifestVersion int    `json:"manifest_version"`
	DefaultLocale   string `json:"default_locale"`
	UpdateURL       string `json:"update_url"`
	Permissions     []any  `json:"permissions"`
	OptionalPerms   []any  `json:"optional_permissions"`
	HostPermissions []any  `json:"host_permissions"`
	ContentScripts  []struct {
		Matches   []string `json:"matches"`
		JS        []string `json:"js"`
		RunAt     string   `json:"run_at"`
		AllFrames bool     `json:"all_frames"`
	} `json:"content_scripts"`
	Background struct {
		ServiceWorker string   `json:"service_worker"`
		Scripts       []string `json:"scripts"`
	} `json:"background"`
	ExternallyConnectable struct {
		Matches []string `json:"matches"`
	} `json:"externally_connectable"`
	SettingsOverrides map[string]any `json:"chrome_settings_overrides"`
	URLOverrides      map[string]any `json:"chrome_url_overrides"`
	CSP               any            `json:"content_security_policy"`
}

// extInstall describes how the browser installed and judged the extension.
type extInstall struct {
	Location       int   // Chrome Manifest::Location (0 = unknown)
	FromWebstore   *bool // nil = unknown
	CWS            *cwsInfo
	BlocklistState int   // Safe Browsing: 1 malware, 2 vuln, 3 policy, 4 PUA
	DisableReasons []int // Chrome disable_reasons (bit values)
}

type cwsInfo struct {
	IsLive             bool `json:"is-live"`
	IsPresent          bool `json:"is-present"`
	ViolationType      int  `json:"violation-type"`
	UnpublishedLongAgo bool `json:"unpublished-long-ago"`
	NoPrivacyPractice  bool `json:"no-privacy-practice"`
}

// Reason kinds: what the extension *can* do (capability) versus signs that
// it is malicious (signal). Powerful legitimate extensions (wallets, VPNs,
// security plug-ins) have high capability but no signals, so capability only
// counts for a third of the score and cannot push it above "medium" alone.
const (
	kindCapability = "cap"
	kindSignal     = "sig"
)

type riskReason struct {
	Code   string `json:"code"`
	Points int    `json:"points"`
	Text   string `json:"text"`
	Kind   string `json:"kind"`
}

type extRisk struct {
	Score      int // Signal + Capability/3
	Signal     int
	Capability int
	Level      string // low / medium / high / critical
	Reasons    []riskReason
}

func (r extRisk) codes() []string {
	out := make([]string, 0, len(r.Reasons))
	for _, x := range r.Reasons {
		out = append(out, x.Code)
	}
	sort.Strings(out)
	return out
}

// summary lists signals first, then capabilities.
func (r extRisk) summary(n int) string {
	var parts []string
	for i, x := range r.Reasons {
		if i >= n {
			parts = append(parts, fmt.Sprintf("외 %d건", len(r.Reasons)-n))
			break
		}
		parts = append(parts, x.Text)
	}
	return strings.Join(parts, "; ")
}

func riskLevel(score int) string {
	switch {
	case score >= 60:
		return SevCritical
	case score >= 35:
		return SevHigh
	case score >= 15:
		return SevMedium
	}
	return SevLow
}

// Chrome Manifest::Location values
const (
	locInternal          = 1
	locExternalPref      = 2
	locExternalRegistry  = 3
	locUnpacked          = 4
	locComponent         = 5
	locExtPrefDownload   = 6
	locExtPolicyDownload = 7
	locCommandLine       = 8
	locExternalPolicy    = 9
	locExtComponent      = 10
)

func isComponentLocation(l int) bool { return l == locComponent || l == locExtComponent }

var permPoints = map[string]struct {
	pts  int
	text string
}{
	"debugger":                            {30, "debugger 권한 (탭 완전 제어·모든 데이터 열람)"},
	"proxy":                               {20, "proxy 권한 (트래픽 우회·가로채기)"},
	"nativeMessaging":                     {15, "nativeMessaging 권한 (로컬 프로그램과 통신)"},
	"management":                          {15, "management 권한 (다른 확장 비활성화 가능)"},
	"clipboardRead":                       {15, "clipboardRead 권한"},
	"webRequestBlocking":                  {15, "webRequestBlocking 권한 (요청 변조)"},
	"cookies":                             {10, "cookies 권한"},
	"privacy":                             {10, "privacy 권한 (브라우저 보안 설정 변경)"},
	"contentSettings":                     {10, "contentSettings 권한"},
	"desktopCapture":                      {10, "desktopCapture 권한 (화면 캡처)"},
	"tabCapture":                          {10, "tabCapture 권한"},
	"webRequest":                          {5, "webRequest 권한"},
	"history":                             {5, "history 권한"},
	"downloads":                           {5, "downloads 권한"},
	"browsingData":                        {5, "browsingData 권한"},
	"scripting":                           {5, "scripting 권한"},
	"declarativeNetRequestWithHostAccess": {5, "declarativeNetRequestWithHostAccess 권한"},
}

var trustedUpdateHosts = []string{
	"https://clients2.google.com/service/update2/crx",
	"https://edge.microsoft.com/extensionwebstorebase/v1/crx",
	"https://extensionwebstorebase.edgesv2.microsoft.com",
	"https://update.googleapis.com/service/update2",
	"http://clients2.google.com/service/update2/crx",
	"https://store.whale.naver.com",
}

func trustedUpdateURL(u string) bool {
	for _, h := range trustedUpdateHosts {
		if strings.HasPrefix(u, h) {
			return true
		}
	}
	return false
}

func anyStrings(v []any) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// manifestPerms returns API permissions and whether every site is reachable.
func manifestPerms(m *extManifest) (perms []string, allSites bool) {
	for _, p := range append(anyStrings(m.Permissions), anyStrings(m.OptionalPerms)...) {
		if isAllSites(p) {
			allSites = true
			continue
		}
		if !slices.Contains(perms, p) {
			perms = append(perms, p)
		}
	}
	for _, h := range anyStrings(m.HostPermissions) {
		if isAllSites(h) {
			allSites = true
		}
	}
	for _, cs := range m.ContentScripts {
		if slices.ContainsFunc(cs.Matches, isAllSites) {
			allSites = true
		}
	}
	sort.Strings(perms)
	return perms, allSites
}

func isAllSites(m string) bool {
	switch m {
	case "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/":
		return true
	}
	return false
}

// assessExtension scores one extension. codeHits are results of scanExtCode.
func assessExtension(m *extManifest, inst extInstall, codeHits []riskReason) extRisk {
	var r extRisk
	add := func(code string, pts int, text string) {
		r.Reasons = append(r.Reasons, riskReason{code, pts, text, kindSignal})
		r.Signal += pts
	}
	capability := func(code string, pts int, text string) {
		r.Reasons = append(r.Reasons, riskReason{code, pts, text, kindCapability})
		r.Capability += pts
	}

	// --- browser verdicts (strongest signals) ---
	switch inst.BlocklistState {
	case 1:
		add("chrome_blocklist_malware", 100, "Chrome Safe Browsing 이 악성으로 차단")
	case 2, 3, 4:
		add("chrome_blocklist", 50, fmt.Sprintf("Chrome Safe Browsing 차단 목록 (state %d: 취약점/정책 위반/PUA)", inst.BlocklistState))
	}
	if c := inst.CWS; c != nil {
		if c.ViolationType != 0 {
			add("cws_violation", 60, fmt.Sprintf("Chrome 웹스토어 위반 판정 (violation-type %d: 악성/정책 위반)", c.ViolationType))
		}
		if !c.IsLive || !c.IsPresent {
			add("cws_removed", 30, "Chrome 웹스토어에서 내려간 확장")
		}
		if c.UnpublishedLongAgo {
			add("cws_unpublished", 10, "오래전에 게시 중단됨")
		}
		if c.NoPrivacyPractice {
			add("cws_no_privacy", 5, "개인정보 처리방침 미기재")
		}
	}
	for _, d := range inst.DisableReasons {
		switch {
		case d&512 != 0:
			add("chrome_corrupted", 40, "Chrome 무결성 검증 실패 — 설치 후 파일이 변조됨")
		case d&256 != 0:
			add("chrome_greylist", 40, "Chrome 이 위험 확장(greylist)으로 비활성화")
		case d&128 != 0:
			add("chrome_not_verified", 20, "Chrome 이 출처를 확인하지 못해 비활성화")
		}
	}

	// --- install source ---
	switch inst.Location {
	case locCommandLine:
		add("loc_command_line", 35, "--load-extension 명령줄로 강제 로드 (ChromeLoader 계열 수법)")
	case locUnpacked:
		add("loc_unpacked", 20, "개발자 모드로 로드한 압축해제 확장 (웹스토어 검수 없음)")
	case locExternalPref, locExternalRegistry, locExtPrefDownload:
		if inst.FromWebstore == nil || !*inst.FromWebstore {
			add("loc_sideloaded", 20, "외부 프로그램이 사이드로드한 확장")
		}
	case locExternalPolicy, locExtPolicyDownload:
		add("loc_policy", 10, "정책(MDM/구성 프로파일)으로 강제 설치")
	}
	if m.UpdateURL != "" && !trustedUpdateURL(m.UpdateURL) {
		add("self_hosted_update", 15, "웹스토어가 아닌 자체 서버에서 업데이트 ("+m.UpdateURL+")")
	} else if inst.FromWebstore != nil && !*inst.FromWebstore && inst.Location == locInternal {
		add("not_from_webstore", 10, "웹스토어 외부에서 설치")
	}

	// --- permissions ---
	perms, allSites := manifestPerms(m)
	for _, p := range perms {
		if pp, ok := permPoints[p]; ok {
			capability("perm_"+p, pp.pts, pp.text)
		}
	}
	if allSites {
		capability("all_sites", 15, "모든 사이트의 페이지를 읽고 변경 가능")
		if slices.Contains(perms, "cookies") {
			capability("cookies_all_sites", 10, "모든 사이트의 쿠키 접근 (세션 탈취 가능)")
		}
	}
	for _, cs := range m.ContentScripts {
		if slices.ContainsFunc(cs.Matches, isAllSites) && cs.AllFrames && cs.RunAt == "document_start" {
			capability("cs_early_all_frames", 5, "모든 사이트·모든 프레임에 페이지 로드 전 스크립트 주입")
			break
		}
	}
	if slices.ContainsFunc(m.ExternallyConnectable.Matches, isAllSites) {
		capability("externally_connectable_all", 10, "모든 웹사이트가 확장과 통신 가능")
	}
	if _, ok := m.SettingsOverrides["search_provider"]; ok {
		capability("search_override", 15, "기본 검색엔진 변경 (검색 하이재킹 애드웨어 수법)")
	} else if len(m.SettingsOverrides) > 0 {
		capability("settings_override", 10, "홈페이지/시작 페이지 변경")
	}
	if _, ok := m.URLOverrides["newtab"]; ok {
		capability("newtab_override", 5, "새 탭 페이지 교체")
	}
	if strings.Contains(fmt.Sprint(m.CSP), "unsafe-eval") {
		capability("csp_unsafe_eval", 10, "CSP 에 unsafe-eval 허용 (동적 코드 실행)")
	}

	// --- code ---
	for _, h := range codeHits {
		add(h.Code, h.Points, h.Text)
	}

	sort.SliceStable(r.Reasons, func(i, j int) bool {
		if r.Reasons[i].Kind != r.Reasons[j].Kind {
			return r.Reasons[i].Kind == kindSignal
		}
		return r.Reasons[i].Points > r.Reasons[j].Points
	})
	r.Score = r.Signal + r.Capability/3
	r.Level = riskLevel(r.Score)
	return r
}

// Wallet extensions commonly targeted by stealers (their IDs appear in the
// stealer's code to locate the wallet's local storage).
var walletExtIDs = map[string]string{
	"nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
	"bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
	"hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
	"ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
	"egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
	"fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
}

var (
	reNetSend       = regexp.MustCompile(`\bfetch\(|XMLHttpRequest|sendBeacon\(|new WebSocket\(|\$\.ajax\(|axios\.`)
	reCookiesGetAll = regexp.MustCompile(`chrome\.cookies\.getAll|browser\.cookies\.getAll`)
	reKeyListener   = regexp.MustCompile(`addEventListener\(\s*["'](keydown|keypress|keyup)["']|\.onkey(down|press|up)\s*=`)
	rePasswordField = regexp.MustCompile(`type=["']?password|\[type=["']?password|type\s*===?\s*["']password["']`)
	reRemoteScript  = regexp.MustCompile(`createElement\(\s*["']script["']\s*\)[\s\S]{0,300}\.src\s*=\s*["']https?://`)
	// eval of decoded or downloaded text (not merely "uses eval somewhere")
	reEvalRemote  = regexp.MustCompile(`(?:\beval|new Function)\(\s*(?:atob|unescape|decodeURIComponent)\(|\.then\(\s*(?:eval|Function)\s*\)|(?:\beval|new Function)\(\s*\(?\s*await\s+(?:fetch|\w+\.text\(\))`)
	reMgmtDisable = regexp.MustCompile(`chrome\.management\.(setEnabled|uninstall)\(`)
	reCSPStrip    = regexp.MustCompile(`(?i)onHeadersReceived[\s\S]{0,800}content-security-policy`)
	reObfuscated  = regexp.MustCompile(`_0x[0-9a-f]{4,6}`)
)

const (
	extMaxFiles     = 400
	extMaxFileBytes = 8 << 20
	extMaxTotal     = 48 << 20
)

// scanExtCode looks for stealer / clipper / keylogger patterns in an
// extension's JavaScript. Each indicator is reported once.
func scanExtCode(dir, selfID string) []riskReason {
	var hits []riskReason
	seen := map[string]bool{}
	hit := func(code string, pts int, text string) {
		if !seen[code] {
			seen[code] = true
			hits = append(hits, riskReason{code, pts, text, kindSignal})
		}
	}
	files, total := 0, int64(0)
	_ = filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
		if err != nil || files >= extMaxFiles || total >= extMaxTotal {
			return nil
		}
		if de.IsDir() {
			if de.Name() == "_metadata" || de.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".js") && !strings.HasSuffix(p, ".mjs") {
			return nil
		}
		info, err := de.Info()
		if err != nil || info.Size() > extMaxFileBytes {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files++
		total += int64(len(b))
		name := filepath.Base(p)
		send := reNetSend.Match(b)

		if reCopyListener.Match(b) && reSetClipData.Match(b) && reWalletRegex.Match(b) {
			hit("code_clipper", 60, "클리퍼 코드: copy 이벤트 후킹 + 클립보드 덮어쓰기 + 지갑 주소 정규식 ("+name+")")
		}
		if reCookiesGetAll.Match(b) && send {
			hit("code_cookie_exfil", 20, "쿠키 일괄 수집 + 네트워크 전송 코드 ("+name+")")
		}
		if reKeyListener.Match(b) && send && rePasswordField.Match(b) {
			hit("code_keylogger", 25, "키 입력·비밀번호 필드 수집 + 전송 코드 — 키로거/폼 그래버 의심 ("+name+")")
		}
		if reRemoteScript.Match(b) {
			hit("code_remote_script", 15, "외부 서버 스크립트를 페이지에 주입 ("+name+")")
		}
		if reEvalRemote.Match(b) {
			hit("code_eval_remote", 20, "디코딩/다운로드한 문자열을 eval 로 실행 (원격 코드 실행) ("+name+")")
		}
		if reMgmtDisable.Match(b) {
			hit("code_disable_others", 15, "다른 확장을 비활성화/삭제하는 코드 ("+name+")")
		}
		if reCSPStrip.Match(b) {
			hit("code_csp_strip", 15, "응답의 보안 헤더(CSP) 제거 코드 ("+name+")")
		}
		if len(reObfuscated.FindAllIndex(b, 60)) >= 60 {
			hit("code_obfuscated", 10, "javascript-obfuscator 형태의 난독화 코드 ("+name+")")
		}
		_, selfIsWallet := walletExtIDs[selfID]
		for id, wallet := range walletExtIDs {
			if !selfIsWallet && bytes.Contains(b, []byte(id)) {
				hit("code_wallet_targets", 25, "다른 지갑 확장 ID 참조 ("+wallet+" 등) — 지갑 데이터 탈취 대상 목록 의심 ("+name+")")
				break
			}
		}
		return nil
	})
	return hits
}

// disableReasonText decodes Chrome disable_reasons for display.
func disableReasonText(reasons []int) string {
	names := map[int]string{
		1: "사용자", 4: "권한 확대", 8: "재로드", 16: "요구사항 미지원", 32: "사이드로드 정리",
		128: "출처 미확인", 256: "greylist", 512: "파일 변조", 1024: "원격 설치", 4096: "외부 확장",
		8192: "정책 업데이트 필요", 32768: "정책 차단", 65536: "재설치", 131072: "allowlist 아님",
	}
	var out []string
	for _, r := range reasons {
		found := false
		for bit, n := range names {
			if r&bit != 0 {
				out = append(out, n)
				found = true
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("reason %d", r))
		}
	}
	sort.Strings(out)
	return strings.Join(slices.Compact(out), ", ")
}

var (
	reCopyListener = regexp.MustCompile(`addEventListener\(\s*["'\x60]copy["'\x60]|\.oncopy\s*=|on\(\s*["']copy["']`)
	reSetClipData  = regexp.MustCompile(`clipboardData\.setData|navigator\.clipboard\.writeText|execCommand\(\s*["']copy["']`)
	reWalletRegex  = regexp.MustCompile(`0x\[0-9a-fA-F\]\{40\}|0x\[a-fA-F0-9\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|bc1\[|\^T\[|\[1-9A-HJ-NP-Za-km-z\]\{3[23]`)
)

// clipperCodeIndicator looks for the in-page clipper recipe in content
// scripts: a copy-event hook that rewrites clipboard data plus a wallet
// address regular expression.
func clipperCodeIndicator(scripts []string) string {
	for _, p := range scripts {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > 8<<20 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if reCopyListener.Match(b) && reSetClipData.Match(b) && reWalletRegex.Match(b) {
			return "copy 이벤트 후킹 + 클립보드 덮어쓰기 + 지갑 주소 정규식 (" + filepath.Base(p) + ")"
		}
	}
	return ""
}
