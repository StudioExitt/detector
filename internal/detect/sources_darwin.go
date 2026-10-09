package detect

// detectorSources describes what each detector inspects on macOS.
func detectorSources(name string) []string {
	return map[string][]string{
		"auth": {
			"unified log: opendirectoryd \"Authentication failed\" (잠금화면, sudo, 암호 입력창, SSH 비밀번호)",
			"unified log: sshd / sshd-session (Failed / Invalid user / Accepted)",
			"unified log: sudo (incorrect password attempts, NOT in sudoers)",
			"dscl: GeneratedUID → 사용자 이름 변환",
		},
		"fim": {
			"sha256 해시 + 권한 비교 (읽기 불가 파일은 크기/수정시각)",
			"LaunchDaemons / LaunchAgents plist → plutil 로 실행 프로그램 확인, codesign 서명 검사",
			"sudoers, pam.d, sshd_config, authorized_keys, 셸 시작 파일, cron, hosts, loginwindow",
		},
		"listeners": {"netstat -anv -p tcp (모든 소켓의 PID)", "ps -o comm (PID → 실행 경로)"},
		"process":   {"ps -o pid,user,comm / pid,args", "lsof -d txt (상대경로 실행 파일의 실제 경로)"},
		"accounts":  {"dscl . -list /Users UniqueID, UserShell", "dscl . -read /Groups/admin GroupMembership"},
		"posture": {
			"csrutil status, spctl --status", "socketfilterfw (방화벽, 스텔스 모드)", "fdesetup status",
			"launchctl print (sshd, screensharing), ARDAgent 프로세스",
			"defaults: loginwindow (자동 로그인, 게스트), SoftwareUpdate (자동 보안 업데이트, 대기 업데이트)",
		},
	}[name]
}
