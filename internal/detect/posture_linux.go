package detect

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
)

func postureChecks() []postureCheck {
	return []postureCheck{
		sshdOption("ssh_root_login", "SSH root 로그인", SevHigh, "permitrootlogin", "prohibit-password",
			func(v string) bool {
				return v == "no" || v == "prohibit-password" || v == "without-password" || v == "forced-commands-only"
			},
			"root 비밀번호 로그인 허용"),
		sshdOption("ssh_password_auth", "SSH 비밀번호 인증", SevMedium, "passwordauthentication", "yes",
			func(v string) bool { return v == "no" }, "비밀번호 인증 허용 — 무차별 대입 대상 (공개키 인증 권장)"),
		sshdOption("ssh_empty_passwords", "SSH 빈 비밀번호 허용", SevHigh, "permitemptypasswords", "no",
			func(v string) bool { return v == "no" }, "빈 비밀번호 로그인 허용"),
		{ID: "aslr", Title: "ASLR (kernel.randomize_va_space)", Severity: SevMedium, Run: func(context.Context) (string, string, error) {
			b, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
			if err != nil {
				return "", "", err
			}
			if v := strings.TrimSpace(string(b)); v != "2" {
				return CheckWarn, "값 " + v + " — 2(전체) 권장", nil
			}
			return CheckOK, "2", nil
		}},
		{ID: "lsm", Title: "SELinux / AppArmor", Severity: SevLow, Run: func(context.Context) (string, string, error) {
			if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
				if strings.TrimSpace(string(b)) == "1" {
					return CheckOK, "SELinux enforcing", nil
				}
				return CheckWarn, "SELinux permissive", nil
			}
			if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil && strings.TrimSpace(string(b)) == "Y" {
				return CheckOK, "AppArmor enabled", nil
			}
			return CheckWarn, "사용 안 함", nil
		}},
	}
}

// sshdOption checks an sshd_config keyword (first occurrence wins, like sshd).
func sshdOption(id, title, sev, key, def string, ok func(string) bool, weakDetail string) postureCheck {
	return postureCheck{ID: id, Title: title, Severity: sev, Run: func(context.Context) (string, string, error) {
		if _, err := os.Stat("/etc/ssh/sshd_config"); err != nil {
			return CheckOK, "sshd 미설치", nil
		}
		v, src := sshdValue(key)
		if v == "" {
			v, src = def, "기본값"
		}
		if ok(strings.ToLower(v)) {
			return CheckOK, v + " (" + src + ")", nil
		}
		return CheckWarn, v + " (" + src + ") — " + weakDetail, nil
	}}
}

func sshdValue(key string) (string, string) {
	files, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	files = append(files, "/etc/ssh/sshd_config") // Include in the main file is processed first on modern distros
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		inMatch := false
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 2 || strings.HasPrefix(fs[0], "#") {
				continue
			}
			k := strings.ToLower(fs[0])
			if k == "match" {
				inMatch = true
			}
			if !inMatch && k == key {
				f.Close()
				return fs[1], p
			}
		}
		f.Close()
	}
	return "", ""
}
