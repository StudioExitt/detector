package detect

// detectorSources describes what each detector inspects on Linux.
func detectorSources(name string) []string {
	return map[string][]string{
		"auth": {
			"/var/log/auth.log 또는 /var/log/secure (오프셋 이어 읽기, 로테이션 감지)",
			"파일이 없으면 journalctl -t sshd -t sshd-session -t sudo",
		},
		"fim": {
			"sha256 해시 + 권한 비교 (읽기 불가 파일은 크기/수정시각)",
			"passwd/shadow/group, sudoers, pam.d, sshd_config, authorized_keys",
			"cron, systemd, init.d, rc.local, ld.so.preload, modules-load.d, 셸 시작 파일",
		},
		"listeners": {"/proc/net/tcp, /proc/net/tcp6 (state 0A)", "/proc/<pid>/fd 소켓 inode → 프로세스"},
		"process":   {"/proc/<pid>/exe, cmdline, 소유자", "삭제된 실행 파일 (exe → \"(deleted)\")"},
		"accounts":  {"/etc/passwd, /etc/group (sudo, wheel, admin)", "/etc/shadow (빈 비밀번호, root 필요)"},
		"posture":   {"sshd_config(.d) PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords", "/proc/sys/kernel/randomize_va_space", "SELinux / AppArmor"},
	}[name]
}
