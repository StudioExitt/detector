package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func fimRules() []fimRule {
	return []fimRule{
		// privilege & authentication
		{"/etc/sudoers", SevHigh, "sudo 권한 설정"},
		{"/etc/sudoers.d", SevHigh, "sudo 권한 설정"},
		{"/etc/pam.d", SevHigh, "PAM 인증 모듈 설정"},
		{"/etc/ssh/sshd_config", SevHigh, "SSH 서버 설정"},
		{"/etc/ssh/sshd_config.d", SevHigh, "SSH 서버 설정"},
		{"/Users/*/.ssh/authorized_keys", SevHigh, "SSH 공개키 로그인 허용 목록 (백도어로 악용)"},
		{"/var/root/.ssh/authorized_keys", SevCritical, "root SSH 공개키"},
		{"/Library/Security/SecurityAgentPlugins", SevHigh, "인증 플러그인 (로그인 가로채기 악용)"},
		// persistence
		{"/Library/LaunchDaemons", SevHigh, "시스템 부팅 시 root 로 자동 실행 (launchd 데몬)"},
		{"/Library/LaunchAgents", SevHigh, "모든 사용자 로그인 시 자동 실행 (launchd 에이전트)"},
		{"/Users/*/Library/LaunchAgents", SevHigh, "사용자 로그인 시 자동 실행 (launchd 에이전트)"},
		{"/Library/StartupItems", SevHigh, "레거시 시작 항목"},
		{"/usr/lib/cron/tabs", SevHigh, "cron 예약 작업"},
		{"/etc/periodic", SevMedium, "주기 실행 스크립트"},
		{"/Library/Preferences/com.apple.loginwindow.plist", SevMedium, "로그인 창 설정 (LoginHook, 자동 로그인)"},
		// shell startup (code runs in every new terminal)
		{"/etc/zshrc", SevMedium, "셸 시작 스크립트"},
		{"/etc/zprofile", SevMedium, "셸 시작 스크립트"},
		{"/etc/profile", SevMedium, "셸 시작 스크립트"},
		{"/etc/bashrc", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.zshrc", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.zshenv", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.zprofile", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.zlogin", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.bash_profile", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.bashrc", SevMedium, "셸 시작 스크립트"},
		{"/Users/*/.profile", SevMedium, "셸 시작 스크립트"},
		// name resolution / PATH
		{"/etc/hosts", SevMedium, "호스트 이름 해석 (피싱/차단 우회 악용)"},
		{"/etc/paths", SevMedium, "PATH 설정"},
		{"/etc/paths.d", SevMedium, "PATH 설정"},
		{"/etc/resolver", SevMedium, "DNS 리졸버 설정"},
	}
}

// fimEnrich inspects launchd plists: which program they start and whether it
// is code-signed. Unsigned or temp-dir programs bump the severity.
func fimEnrich(ctx context.Context, path string) (string, bool) {
	if !strings.HasSuffix(path, ".plist") || !strings.Contains(path, "/Launch") {
		return "", false
	}
	out, err := runCmd(ctx, 10*time.Second, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		return "", false
	}
	var pl struct {
		Label            string   `json:"Label"`
		Program          string   `json:"Program"`
		ProgramArguments []string `json:"ProgramArguments"`
		RunAtLoad        bool     `json:"RunAtLoad"`
		KeepAlive        any      `json:"KeepAlive"`
	}
	if json.Unmarshal([]byte(out), &pl) != nil {
		return "", false
	}
	prog := pl.Program
	if prog == "" && len(pl.ProgramArguments) > 0 {
		prog = pl.ProgramArguments[0]
	}
	parts := []string{"Label=" + pl.Label, "Program=" + prog}
	if pl.RunAtLoad {
		parts = append(parts, "RunAtLoad")
	}
	if pl.KeepAlive != nil && pl.KeepAlive != false {
		parts = append(parts, "KeepAlive")
	}

	bump := false
	// scan the binary and any script passed as an argument (python/sh/osascript ...)
	targets := []string{prog}
	if len(pl.ProgramArguments) > 1 {
		targets = append(targets, pl.ProgramArguments[1:]...)
	}
	if ind := clipperFileIndicator(targets); ind != "" {
		parts = append(parts, "⚠ 클리퍼 특징: "+ind)
		bump = true
	}
	if prog != "" {
		if inSuspiciousDir(prog) || strings.Contains(prog, "/.") {
			parts = append(parts, "⚠ 임시/숨김 경로에서 실행")
			bump = true
		}
		if _, err := os.Stat(prog); err == nil {
			signer, signed := codeSigner(ctx, prog)
			if signed {
				parts = append(parts, "서명="+signer)
			} else {
				parts = append(parts, "⚠ 코드 서명 없음")
				bump = true
			}
		}
	}
	return strings.Join(parts, ", "), bump
}

// codeSigner returns the first signing authority of a binary.
func codeSigner(ctx context.Context, path string) (string, bool) {
	_, err := runCmd(ctx, 15*time.Second, "codesign", "--verify", "--strict", path)
	if err != nil {
		return "", false
	}
	// codesign -dv writes the signing details to stderr
	out, _ := runCmdCombined(ctx, 15*time.Second, "codesign", "-dv", "--verbose=2", path)
	for line := range strings.Lines(out) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Authority="); ok {
			return v, true
		}
	}
	if strings.Contains(out, "Signature=adhoc") {
		return "ad-hoc", true
	}
	return fmt.Sprintf("signed (%s)", path), true
}

var (
	clipAccessMarkers = [][]byte{
		[]byte("NSPasteboard"), []byte("generalPasteboard"), []byte("pbpaste"), []byte("pbcopy"),
		[]byte("the clipboard"), []byte("pyperclip"), []byte("clipboard.ReadAll"), []byte("golang.design/x/clipboard"),
	}
	walletMarkers = [][]byte{
		[]byte("0x[0-9a-fA-F]{40}"), []byte("0x[a-fA-F0-9]{40}"), []byte("[13][a-km-zA-HJ-NP-Z1-9]"),
		[]byte("bc1[a-z0-9]"), []byte("bc1q"), []byte("T[A-Za-z1-9]{33}"), []byte("[1-9A-HJ-NP-Za-km-z]{32,44}"),
	}
)

// clipperFileIndicator reports files that both access the pasteboard and
// carry wallet address patterns — the signature of a clipper.
func clipperFileIndicator(paths []string) string {
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64<<20 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		clip := firstMarker(b, clipAccessMarkers)
		wallet := firstMarker(b, walletMarkers)
		if clip != "" && wallet != "" {
			return fmt.Sprintf("%s 에 클립보드 접근(%s) + 지갑 주소 패턴(%s)", filepath.Base(p), clip, wallet)
		}
	}
	return ""
}

func firstMarker(b []byte, markers [][]byte) string {
	for _, m := range markers {
		if bytes.Contains(b, m) {
			return string(m)
		}
	}
	return ""
}
