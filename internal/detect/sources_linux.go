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
		"recording": {
			"/proc/asound/card*/pcm*c/sub*/status (RUNNING 인 녹음 장치, owner_pid)",
			"pactl list source-outputs (PulseAudio/PipeWire 녹음 스트림의 앱)",
			"/proc/<pid>/fd → /dev/video* (카메라를 연 프로세스)",
			"/proc: 화면/오디오 녹화 도구, 원격 화면 보기·제어 도구 (화면 캡처 자체는 OS 가 알려주지 않음)",
		},
		"usb": {
			"/sys/bus/usb/devices: USB 장치(제조사·제품·시리얼·VID:PID), 인터페이스 종류",
			"/sys/block/<dev> (USB 경로), stat: 외장 디스크와 읽기/쓰기 섹터",
			"/proc/self/mountinfo, /dev/disk/by-label: 마운트 위치·파일시스템·라벨",
			"/proc/<pid>/fd, cwd, root, exe: 디스크·/dev/bus/usb 장치를 사용 중인 프로세스",
			"조치: kill(SIGTERM→SIGKILL), udisksctl unmount/power-off (없으면 umount/eject), umount -f / -l",
		},
	}[name]
}
