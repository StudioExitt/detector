package detect

import "context"

func fimRules() []fimRule {
	return []fimRule{
		// accounts & privilege
		{"/etc/passwd", SevHigh, "계정 목록"},
		{"/etc/shadow", SevHigh, "계정 비밀번호 해시"},
		{"/etc/group", SevHigh, "그룹 (sudo/wheel 멤버)"},
		{"/etc/gshadow", SevHigh, "그룹 비밀번호"},
		{"/etc/sudoers", SevHigh, "sudo 권한 설정"},
		{"/etc/sudoers.d", SevHigh, "sudo 권한 설정"},
		{"/etc/pam.d", SevHigh, "PAM 인증 모듈 설정"},
		{"/etc/security", SevMedium, "PAM 보안 정책"},
		{"/etc/ssh/sshd_config", SevHigh, "SSH 서버 설정"},
		{"/etc/ssh/sshd_config.d", SevHigh, "SSH 서버 설정"},
		{"/root/.ssh/authorized_keys", SevCritical, "root SSH 공개키"},
		{"/home/*/.ssh/authorized_keys", SevHigh, "SSH 공개키 로그인 허용 목록 (백도어로 악용)"},
		// persistence
		{"/etc/crontab", SevHigh, "cron 예약 작업"},
		{"/etc/cron.d", SevHigh, "cron 예약 작업"},
		{"/etc/cron.hourly", SevHigh, "cron 예약 작업"},
		{"/etc/cron.daily", SevMedium, "cron 예약 작업"},
		{"/etc/cron.weekly", SevMedium, "cron 예약 작업"},
		{"/etc/cron.monthly", SevMedium, "cron 예약 작업"},
		{"/var/spool/cron", SevHigh, "사용자 crontab"},
		{"/etc/systemd/system", SevHigh, "systemd 서비스/타이머 (자동 실행)"},
		{"/etc/init.d", SevMedium, "SysV init 스크립트"},
		{"/etc/rc.local", SevHigh, "부팅 시 실행 스크립트"},
		{"/etc/ld.so.preload", SevCritical, "모든 프로세스에 라이브러리 주입 (루트킷 단골)"},
		{"/etc/ld.so.conf.d", SevMedium, "공유 라이브러리 경로"},
		{"/etc/modules-load.d", SevHigh, "부팅 시 커널 모듈 로드"},
		{"/etc/udev/rules.d", SevMedium, "udev 규칙 (장치 이벤트 시 실행)"},
		// shell startup
		{"/etc/profile", SevMedium, "셸 시작 스크립트"},
		{"/etc/profile.d", SevMedium, "셸 시작 스크립트"},
		{"/etc/bash.bashrc", SevMedium, "셸 시작 스크립트"},
		{"/etc/bashrc", SevMedium, "셸 시작 스크립트"},
		{"/root/.bashrc", SevHigh, "root 셸 시작 스크립트"},
		{"/root/.profile", SevHigh, "root 셸 시작 스크립트"},
		{"/home/*/.bashrc", SevMedium, "셸 시작 스크립트"},
		{"/home/*/.profile", SevMedium, "셸 시작 스크립트"},
		{"/home/*/.bash_profile", SevMedium, "셸 시작 스크립트"},
		// name resolution
		{"/etc/hosts", SevMedium, "호스트 이름 해석"},
		{"/etc/resolv.conf", SevLow, "DNS 리졸버 설정"},
	}
}

func fimEnrich(context.Context, string) (string, bool) { return "", false }
