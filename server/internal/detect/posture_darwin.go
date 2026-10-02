package detect

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const cmdTimeout = 15 * time.Second

func postureChecks() []postureCheck {
	return []postureCheck{
		{ID: "sip", Title: "SIP (System Integrity Protection)", Severity: SevHigh, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "csrutil", "status")
			if err != nil {
				return "", "", err
			}
			if strings.Contains(out, "status: enabled") {
				return CheckOK, "enabled", nil
			}
			return CheckFail, strings.TrimSpace(firstLine(out)), nil
		}},
		{ID: "gatekeeper", Title: "Gatekeeper", Severity: SevHigh, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "spctl", "--status")
			if strings.Contains(out, "assessments enabled") {
				return CheckOK, "assessments enabled", nil
			}
			if strings.Contains(out, "assessments disabled") {
				return CheckFail, "assessments disabled — 서명/공증 안 된 앱 실행 허용", nil
			}
			return "", "", err
		}},
		{ID: "firewall", Title: "애플리케이션 방화벽", Severity: SevMedium, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
			if err != nil {
				return "", "", err
			}
			if strings.Contains(out, "enabled") {
				return CheckOK, strings.TrimSpace(out), nil
			}
			return CheckWarn, "꺼짐 — 외부에서 리스닝 포트로 접근 가능", nil
		}},
		{ID: "firewall_stealth", Title: "방화벽 스텔스 모드", Severity: SevLow, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
			if err != nil {
				return "", "", err
			}
			if strings.Contains(out, "is on") || strings.Contains(out, "enabled") {
				return CheckOK, "on", nil
			}
			return CheckWarn, "꺼짐 — ping/포트 스캔에 응답", nil
		}},
		{ID: "filevault", Title: "FileVault 디스크 암호화", Severity: SevMedium, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "fdesetup", "status")
			if err != nil {
				return "", "", err
			}
			if strings.Contains(out, "FileVault is On") {
				return CheckOK, "On", nil
			}
			return CheckWarn, strings.TrimSpace(firstLine(out)) + " — 분실/도난 시 데이터 노출", nil
		}},
		{ID: "remote_login", Title: "원격 로그인 (SSH)", Severity: SevLow, Run: launchdServiceCheck("com.openssh.sshd", "켜짐 — SSH 무차별 대입 대상")},
		{ID: "screen_sharing", Title: "화면 공유 (VNC)", Severity: SevMedium, Run: launchdServiceCheck("com.apple.screensharing", "켜짐 — 원격 화면 제어 가능")},
		{ID: "remote_management", Title: "원격 관리 (ARD)", Severity: SevMedium, Run: func(ctx context.Context) (string, string, error) {
			// ARDAgent runs only when Remote Management is enabled
			out, err := runCmd(ctx, cmdTimeout, "pgrep", "-x", "ARDAgent")
			if err == nil && strings.TrimSpace(out) != "" {
				return CheckWarn, "켜짐 — 원격 관리 에이전트 실행 중", nil
			}
			if exitCode(err) == 1 {
				return CheckOK, "꺼짐", nil
			}
			return "", "", err
		}},
		{ID: "auto_login", Title: "자동 로그인", Severity: SevMedium, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
			if err != nil {
				return CheckOK, "꺼짐", nil // key absent
			}
			return CheckFail, "켜짐 (" + strings.TrimSpace(out) + ") — 부팅 시 암호 없이 로그인", nil
		}},
		{ID: "guest", Title: "게스트 계정", Severity: SevLow, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
			if err != nil || strings.TrimSpace(out) != "1" {
				return CheckOK, "꺼짐", nil
			}
			return CheckWarn, "켜짐", nil
		}},
		{ID: "auto_security_updates", Title: "보안 업데이트 자동 설치", Severity: SevMedium, Run: func(ctx context.Context) (string, string, error) {
			for _, key := range []string{"CriticalUpdateInstall", "ConfigDataInstall"} {
				out, err := runCmd(ctx, cmdTimeout, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key)
				if err == nil && strings.TrimSpace(out) == "0" {
					return CheckWarn, key + " = 0 — XProtect/보안 응답 자동 설치 꺼짐", nil
				}
			}
			return CheckOK, "켜짐 (기본값)", nil
		}},
		{ID: "pending_updates", Title: "대기 중인 소프트웨어 업데이트", Severity: SevLow, Run: func(ctx context.Context) (string, string, error) {
			out, err := runCmd(ctx, cmdTimeout, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastRecommendedUpdatesAvailable")
			if err != nil {
				return CheckOK, "없음", nil
			}
			n, _ := strconv.Atoi(strings.TrimSpace(out))
			if n == 0 {
				return CheckOK, "없음", nil
			}
			return CheckWarn, fmt.Sprintf("%d건 — 보안 패치 미적용 가능성", n), nil
		}},
	}
}

// launchdServiceCheck reports whether a system launchd service is loaded
// (`launchctl print` exits 113 when the service is not loaded).
func launchdServiceCheck(label, onDetail string) func(context.Context) (string, string, error) {
	return func(ctx context.Context) (string, string, error) {
		_, err := runCmd(ctx, cmdTimeout, "launchctl", "print", "system/"+label)
		switch exitCode(err) {
		case 0:
			return CheckWarn, onDetail, nil
		case 113:
			return CheckOK, "꺼짐", nil
		}
		return "", "", err
	}
}
