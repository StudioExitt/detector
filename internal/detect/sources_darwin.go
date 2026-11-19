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
		"recording": {
			"unified log stream: ControlCenter sensor-indicators (메뉴 막대 화면 녹화·마이크·카메라 표시등, 앱 확인 불가 캡처의 PID)",
			"CoreAudio: 입력 장치 IsRunningSomewhere, 오디오 입력 중인 프로세스 (macOS 14+)",
			"CoreMediaIO: 카메라 IsRunningSomewhere",
			"TCC.db (시스템·사용자): 화면 기록·마이크·카메라·입력 모니터링 허용 앱 (전체 디스크 접근 권한 필요)",
			"ps: 화면/오디오 녹화 도구, 원격 화면 보기·제어 도구",
		},
		"usb": {
			"ioreg -r -c IOUSBHostDevice -a: USB 장치(제조사·제품·시리얼·VID:PID), 인터페이스 종류, 장치를 연 프로세스(IOUserClientCreator), 디스크 읽기/쓰기 바이트",
			"diskutil list/info -plist external: 외장 디스크·볼륨·마운트 위치 (디스크 이미지 제외)",
			"lsof -F (마운트 위치, /dev/diskN, /dev/rdiskN): 디스크를 사용 중인 프로세스",
			"조치: kill(SIGTERM→SIGKILL), diskutil eject, diskutil unmountDisk force",
		},
	}[name]
}
