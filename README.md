# Detector

해킹 흔적, 비정상 시스템 점유, 취약한 보안 설정, 악성 브라우저 확장, 클립보드 지갑 주소 바꿔치기, 몰래 하는 화면 녹화·녹음·촬영 등을 감시하는 **로컬 보안 모니터**입니다.

- Go 서버와 React 웹 UI 가 **단일 바이너리**로 빌드되어, 프로그램 하나만 실행하면 됩니다.
- macOS 를 기준으로 가장 상세하게 감시하며, Linux 도 지원합니다. (클립보드·브라우저 확장 감시는 macOS 전용)

---

## 빠른 시작

**필요 환경:** Go 1.25 이상, Node.js(빌드할 때만 필요)

```sh
make start    # 빌드 → 실행 → 브라우저 열기
```

브라우저에서 **`http://localhost:<apiPort>/detector/`** 로 접속합니다. (`apiPort` 는 `config.toml` 에서 설정)

```sh
make run                             # 빌드 후 실행 (브라우저는 열지 않음)
make build                           # 빌드만 → build/detector
./build/detector -c config.toml      # 빌드된 바이너리 실행 (-open 을 붙이면 브라우저 열기)
```

> 반드시 **프로젝트 루트에서 실행**하세요. `config.toml` 의 `detector.db`, `logs` 가 실행 위치 기준 상대 경로라서, 다른 곳에서 실행하면 새 DB 로 시작합니다.

---

## 화면 구성

| 메뉴 | 내용 |
|---|---|
| 대시보드 | 서버 상태, 탐지기 동작 요약, 최근 이벤트 |
| 침입 탐지 | 침입 관련 탐지 이벤트 |
| 시스템 | CPU·메모리(압박)·스왑·디스크 현황, 사용률 추이 차트, CPU/메모리 상위 프로세스, 자원 이상 이벤트 |
| 네트워크 | 인터넷 연결·지연, 게이트웨이·DNS·프록시, 트래픽/지연/외부 연결 차트, 프로세스별 연결, **연결 목록**(연결 수 타일·프로세스 행 클릭 → 범위/상태/검색 필터), 네트워크 이벤트 |
| 방화벽 | 방화벽 동작 여부, 구성요소별 설정·허용/차단 규칙·설정 파일, 방화벽 변경 이벤트 |
| 녹화 감시 | 화면·마이크·카메라 사용 여부와 사용 중인 앱, 장치 상태, 녹화·원격 도구, 녹화 권한(허용 앱), 최근 사용 기록, 녹화 감시 이벤트 |
| 취약점 점검 | 취약한 보안 설정 등 취약점 이벤트 |
| 전체 이벤트 | 모든 이벤트 |
| 탐지기 상태 | 탐지기별 동작 상태 → 클릭하면 상세 (현재 점검 항목 · 실행 이력 · 탐지 이벤트), 클립보드 카나리아 테스트 |

- 다크/라이트 모드, 한국어/영어 전환 (선택값은 브라우저에 저장)
- 차트는 1h / 6h / 24h / 7d 기간 선택, 마우스를 올리면 시점별 값, "표로 보기" 지원
- 화면은 15초마다 자동 갱신

---

## 프로젝트 구조

```
detector/
├── Makefile              빌드/실행 명령
├── config.toml           실행 설정 (포트, 로그, DB, 탐지기)
├── cmd/detector/         main (실행 플래그, 서버 기동)
├── api/                  OpenAPI 스펙(openapi.yaml)과 생성 코드(api.gen.go)
├── internal/
│   ├── config/           설정 로드·기본값·검증
│   ├── db/               SQLite 열기, 스키마/마이그레이션
│   ├── detect/           탐지 엔진과 탐지기들 (*_darwin.go / *_linux.go 로 OS 별 수집)
│   ├── handler/          API 핸들러
│   ├── server/           라우팅 (/api/v1, /swagger/, /detector/)
│   ├── swagger/          Swagger UI (바이너리에 포함)
│   ├── webui/            웹 UI 임베드 (빌드 시 web/dist 가 internal/webui/dist 로 복사됨)
│   └── logger/           일자별 JSON 로그
├── web/                  React UI 소스
├── build/                빌드 결과 (git 제외)
├── logs/                 로그 (git 제외)
└── detector.db           SQLite DB (git 제외)
```

---

## 빌드 / 실행

| 명령 | 설명 |
|---|---|
| `make build` | 웹 UI 빌드 → 임베드 → `build/detector` (현재 OS/아키텍처) |
| `make run` | 빌드 후 실행 (`CONFIG=다른설정.toml` 로 설정 파일 지정 가능) |
| `make start` | 빌드 후 실행 + 브라우저 열기 |
| `make build-linux` | `build/detector-linux-amd64`, `build/detector-linux-arm64` |
| `make build-linux-amd64` / `make build-linux-arm64` | 아키텍처별 Linux 빌드 |
| `make generate` | `api/openapi.yaml` → `api/api.gen.go` 재생성 (oapi-codegen) |
| `make dev-web` | UI 개발용 Vite 서버 (아래 "UI 개발" 참고) |
| `make test` / `make vet` | 테스트 / 정적 검사 |
| `make clean` | `build/` 삭제 |

- 웹 UI 를 다시 빌드하지 않으려면 `NOWEB=1` (예: `make build NOWEB=1`). 이미 `internal/webui/dist` 에 복사된 UI 를 그대로 넣습니다.
- 모든 바이너리는 CGO 없이 정적 빌드됩니다 (SQLite: modernc.org/sqlite, macOS API: purego).

**실행 플래그**

| 플래그 | 설명 |
|---|---|
| `-c <파일>`, `-config <파일>` | 설정 파일 (필수) |
| `-open` | 기동 후 기본 브라우저로 웹 UI 열기 |
| `-version` | 버전 출력 후 종료 |

---

## 설정 (`config.toml`)

포트 하나로 웹 UI(`/detector/`), API(`/api/v1`), Swagger(`/swagger/`)를 모두 제공합니다. 설정을 바꾼 뒤에는 재시작만 하면 됩니다 (재빌드 불필요).

| 섹션 | 주요 항목 |
|---|---|
| `[common]` | `apiPort` (기본 8088), `logLevel` (debug/info/warn/error, 기본 info), `timeZone` (기본 로컬) |
| `[log]` | `dir`, `prefix`, `stdout` — `<dir>/<prefix>-YYYY-MM-DD.log` 에 JSON 으로 일자별 기록 |
| `[database]` | `dbType = "sqlite3"`, `filePath` — WAL 모드 (`journal_mode(WAL)`, `busy_timeout(10000)`) |
| `[detect]` | `enabled`, `cooldown` (같은 탐지 재등록 억제, 기본 1h), `metricsRetention` (시계열 보관, 기본 168h) |
| `[detect.<탐지기>]` | 공통: `enabled`, `interval` (5초 이상). 탐지기별 임계값은 아래 "탐지 기능" 과 `config.toml` 주석 참고 |

---

## 탐지 기능

서버가 기동되면 OS 에 맞는 탐지기들이 주기적으로 실행되고, 결과는 이벤트(`detector`, `rule`, 심각도 포함)로 저장됩니다.

**공통 동작**
- 첫 실행 때 기준선(baseline)을 저장하고, 이후에는 **변화만** 보고합니다. 기준선과 중복 억제(cooldown)는 재시작해도 유지됩니다.
- 실행마다 결과와 당시 점검 항목이 실행 이력에 남습니다 (탐지기당 최근 500건). 단, **계정·클립보드** 탐지기는 정상 실행은 마지막 1건만, 탐지/오류가 있는 실행은 모두 보관합니다.
- **root 실행 권장** — 일반 사용자로 실행하면 다른 사용자 프로세스 경로, root 전용 파일 내용(크기/수정시각만 비교), Linux auth.log 등을 읽지 못할 수 있습니다. 단, 클립보드 감시는 로그인 사용자 권한으로 실행해야 합니다.

| 탐지기 | 감시 내용 | macOS 수집 | Linux 수집 |
|---|---|---|---|
| `auth` 인증 | SSH 무차별 대입, 실패 후 로그인 성공, 처음 보는 출발지, root 로그인, 로컬 비밀번호(잠금화면·sudo·암호창) 무차별 대입, sudo 실패·권한 없는 sudo | unified log (opendirectoryd, sshd, sudo) | auth.log / secure (없으면 journald) |
| `fim` 파일 무결성 | 자동 실행 위치, sudoers, PAM, SSH 키·설정, 셸 시작 파일, cron, hosts 등의 추가/변경/삭제/권한 변경. 새 LaunchAgent/Daemon 은 실행 프로그램의 **코드 서명**과 **클리퍼 특징**까지 검사 | LaunchAgents/Daemons, plutil, codesign | passwd/shadow/group, systemd, cron, `ld.so.preload` 등 |
| `listeners` 리스닝 포트 | 새로 열린 포트 (프로세스 단위로 묶어 보고) | `netstat -anv` | `/proc/net/tcp*` |
| `process` 프로세스 | 임시 경로 실행, 채굴기, 리버스 셸, 삭제된 실행파일, 브라우저 `--load-extension` 강제 로드 | `ps`, `lsof` | `/proc` |
| `accounts` 계정 | 계정 추가/삭제, 관리자 그룹 변경, root 외 UID 0, 빈 비밀번호 | `dscl` | passwd / group / shadow |
| `posture` 보안 설정 | 취약 설정 (처음 발견 = 취약점, 정상 → 취약 변화 = 침입) | SIP, Gatekeeper, 방화벽·스텔스, FileVault, 원격 로그인·화면 공유·원격 관리, 자동 로그인, 게스트, 보안 업데이트 | sshd 설정, ASLR, SELinux/AppArmor |
| `firewall` 방화벽 | 방화벽 꺼짐, 설정 약화(스텔스·전체 차단 해제, 서명 앱 자동 허용 등), 수신 허용 앱/규칙 추가(스크립트 인터프리터·임시 경로면 high), pf 설정 파일 변경, 서드파티 방화벽 제거 | 애플리케이션 방화벽(`socketfilterfw`), pf(`pfctl` 은 root, 설정 파일은 일반 권한), 네트워크 시스템 확장(Little Snitch, LuLu 등) | ufw, firewalld, nftables, iptables (규칙 조회는 대부분 root) |
| `resources` 시스템 자원 | 프로세스 CPU 장기 점유(채굴 의심), 시스템 CPU 과부하, 메모리 압박, 메모리 과점유, 디스크 부족·급증 | top, vm_stat, sysctl, ps, statfs | `/proc`, PSI, statfs |
| `network` 네트워크 | 의심 포트(백도어·IRC·Tor·채굴 풀) 연결, 임시 경로/서명 없는 프로그램의 외부 통신, 대량 연결·다수 호스트·아웃바운드 스캔, 대용량 업로드(macOS), DNS·프록시·게이트웨이 MAC 변경, 인터넷 끊김 | route, arp, scutil, netstat, codesign | `/proc/net/*`, resolv.conf |
| `recording` 녹화 감시 | 화면 녹화/캡처·마이크 녹음·카메라 촬영 시작, 앱을 확인할 수 없는 캡처, 녹화·원격 화면 도구 실행, 녹화 권한 새로 허용 | ControlCenter 표시등 로그(`log stream`), CoreAudio, CoreMediaIO, TCC.db, ps | ALSA(`/proc/asound`), pactl, `/dev/video*` 를 연 프로세스, `/proc` |
| `clipboard` 클립보드 (macOS) | 지갑 주소 바꿔치기(클리퍼) | NSPasteboard | — |
| `extensions` 브라우저 확장 (macOS) | 악성 확장 (Chrome 계열 + Firefox) | 프로필별 Secure Preferences, manifest, JS 코드, 강제 설치 정책 | — |

<details>
<summary>탐지 규칙(rule) 목록</summary>

| 탐지기 | 규칙 |
|---|---|
| auth | `auth.ssh_bruteforce`, `auth.ssh_success_after_failures`, `auth.ssh_new_source`, `auth.ssh_root_login`, `auth.local_bruteforce`, `auth.sudo_failures`, `auth.sudo_not_allowed` |
| fim | `fim.added`, `fim.modified`, `fim.removed`, `fim.mode_changed` |
| listeners | `net.new_listener` |
| process | `proc.suspicious_path`, `proc.miner`, `proc.reverse_shell`, `proc.deleted_exe`, `proc.browser_load_extension` |
| accounts | `account.added`, `account.removed`, `account.admin_added`, `account.admin_removed`, `account.uid0`, `account.no_password` |
| posture | `posture.<항목>` — macOS: `sip`, `gatekeeper`, `firewall`, `firewall_stealth`, `filevault`, `remote_login`, `screen_sharing`, `remote_management`, `auto_login`, `guest`, `auto_security_updates`, `pending_updates` / Linux: `ssh_root_login`, `ssh_password_auth`, `ssh_empty_passwords`, `aslr`, `lsm` |
| firewall | `firewall.disabled`, `firewall.enabled`, `firewall.removed`, `firewall.setting_changed`, `firewall.rule_added`, `firewall.rule_removed`, `firewall.config_changed` |
| resources | `res.cpu_hog`, `res.cpu_high`, `res.mem_pressure`, `res.mem_hog`, `res.disk_full`, `res.disk_growth` |
| network | `net.suspicious_port`, `net.suspicious_process`, `net.unsigned_process`, `net.conn_flood`, `net.many_hosts`, `net.outbound_scan`, `net.large_upload`, `net.dns_changed`, `net.proxy_set`, `net.proxy_changed`, `net.gateway_mac_changed`, `net.offline` |
| recording | `rec.screen_active`, `rec.mic_active`, `rec.camera_active`, `rec.unattributed_capture`, `rec.tool_running`, `rec.permission_granted` |
| clipboard | `clipboard.address_swapped`, `clipboard.rapid_rewrite`, `clipboard.canary_swapped` |
| extensions | `browser.ext_risky`, `browser.ext_new`, `browser.ext_perm_escalation`, `browser.ext_new_verdict`, `browser.ext_blocklisted`, `browser.ext_policy_install`, `browser.ext_sideload` |

</details>

### 방화벽 (`[detect.firewall]`)

- **macOS**: 애플리케이션 방화벽(켜짐 여부, 모든 수신 차단, 서명된 소프트웨어 자동 허용, 스텔스 모드, 로깅, 앱별 수신 허용/차단 규칙), 패킷 필터 pf(`/etc/pf.conf`·`/etc/pf.anchors/*` 설정 파일 — 실행 상태와 적용 규칙은 root 로 실행할 때만), 서드파티 방화벽(Little Snitch, LuLu, Radio Silence 등)과 기타 네트워크 확장(VPN 등)
- **Linux**: ufw, firewalld, nftables, iptables 상태·기본 정책·규칙 (규칙 조회는 대부분 root 필요)
- 주의 표시: 스크립트 인터프리터(python3, ruby, node …)의 수신 허용 — 어떤 스크립트든 포트를 열 수 있음, 임시 경로 프로그램, 삭제된 앱의 남은 규칙
- 화면의 현재 상태는 조회할 때마다 새로 수집하고, 탐지기는 `interval`(기본 1분)마다 변경을 감시합니다. 방화벽이 꺼져 있다는 사실 자체는 `posture` 탐지기가 한 번 보고합니다.

### 화면 녹화·녹음·촬영 감시 (`[detect.recording]`)

- **macOS — 사용 중인 앱**: 메뉴 막대의 화면 기록(보라색)·마이크(주황색)·카메라(초록색) 표시등과 같은 정보를 ControlCenter 의 `sensor-indicators` 로그에서 실시간(`log stream`)으로 받습니다. 기동 시 최근 1시간 로그로 현재 상태를 복원하고, 수집 주기(`interval`, 기본 10초) 사이에 끝난 짧은 캡처(스크린샷 등)도 한 번은 보고합니다.
- **macOS — 앱 확인 불가 캡처** (`rec.unattributed_capture`, high): macOS 가 앱 이름·경로를 확인하지 못한 화면/마이크/카메라 사용입니다. 로그의 감사 토큰에서 PID 를 꺼내 실행 파일을 함께 기록합니다. 백그라운드 CLI 도구나 숨겨진 프로그램일 수 있습니다.
- **장치 상태**: CoreAudio(입력 장치별 사용 여부, macOS 14+ 는 녹음 중인 프로세스 PID 까지), CoreMediaIO(카메라별 사용 여부). 장치는 사용 중인데 앱을 알 수 없으면 "앱 확인 불가" 로 표시합니다.
- **녹화·원격 도구** (`rec.tool_running`): OBS, ffmpeg 화면/오디오 캡처, `screencapture -v`, Loom, Kap, CleanShot X 등 녹화 도구와 AnyDesk, TeamViewer, RustDesk, Chrome 원격 데스크톱, ScreenConnect, macOS 화면 공유(접속 중), VNC 등 원격 화면 도구. 임시 경로에서 실행되면 high.
- **녹화 권한** (`rec.permission_granted`): 화면 기록·마이크·카메라·입력 모니터링이 허용된 앱 목록(TCC.db). 첫 실행은 기준선만 저장하고 이후 새로 허용된 앱을 보고합니다. 스크립트 인터프리터·임시 경로 프로그램이 허용되면 high. **전체 디스크 접근 권한**(시스템 설정 → 개인정보 보호 및 보안 → 전체 디스크 접근 권한에 detector 바이너리 또는 실행한 터미널 추가)이 있어야 읽을 수 있습니다.
- **Linux**: 녹음은 `/proc/asound` 의 RUNNING 상태 녹음 장치와 `pactl list source-outputs`(데스크톱 사용자 세션에서 실행할 때), 카메라는 `/dev/video*` 를 연 프로세스로 판단합니다. 화면 캡처는 OS 가 알려주지 않으므로 녹화·원격 도구 프로세스로만 판단합니다.
- 같은 앱의 사용은 시작될 때 한 번 보고합니다 (계속 사용 중이면 다시 보고하지 않음). 직접 사용하는 앱(화상회의 등)은 `trustedApps` 에 번들 ID·프로세스 이름·경로를 넣으면 화면에는 표시되지만 이벤트는 만들지 않습니다. 기본값은 macOS 스크린샷 UI(`com.apple.systemuiserver`, `com.apple.screencaptureui`)입니다.
- **한계**: macOS 의 표시등은 앱 단위라서, 터미널에서 실행한 도구는 터미널 앱(예: Terminal, iTerm, Ghostty)으로 표시됩니다. 최근 사용 기록은 메모리에만 있으며 재시작하면 초기화됩니다 (이벤트는 DB 에 남음).

### 시스템 / 네트워크 (`[detect.resources]`, `[detect.network]`)

- **CPU**: 프로세스가 `procCpuPercent`(기본 80%, 100% = 코어 1개) 이상을 `sustain`(기본 5분) 동안 유지하면 탐지. 2코어 이상 점유 또는 임시 경로 프로세스면 high(채굴 의심). macOS 는 SIP 보호 경로의 시스템 프로세스를 자동 제외 (`ignoreProcesses` 로 추가 제외)
- **메모리/디스크**: 메모리 압박 warn·critical, 단일 프로세스 RAM `procMemPercent`(25%) 이상, 디스크 90/95% 이상, 10분 내 `diskGrowthGB`(5GB) 이상 증가
- **네트워크**: `probeTargets`(기본 `1.1.1.1:443`, `8.8.8.8:443`)로 30초마다 인터넷 연결을 확인합니다 — 외부 접속을 원하지 않으면 `probeTargets = []`
- CPU·메모리·디스크·트래픽·지연·연결 수는 시계열로 저장되어 차트로 표시됩니다 (`metricsRetention`, 기본 7일)

### 클립보드 바꿔치기(클리퍼) 탐지 — macOS

- **실시간 감시**: 복사한 지갑 주소(EVM, BTC, LTC, DOGE, TRON, XRP, XMR, TON, SOL)가 `swapWindow`(1초) 안에 같은 체인의 다른 주소로 바뀌면 critical. macOS 에는 클립보드 변경 알림이 없어 클리퍼도 주기적으로 확인하므로, 더 촘촘한 50ms 간격으로 원래 주소를 먼저 관찰합니다. 앞뒤 글자만 맞춘 유사 주소인지도 함께 기록합니다.
- **카나리아 테스트**: 탐지기 상태 → 클립보드 감시 → **테스트 실행** (`POST /api/v1/clipboard/test`). 공개된 미끼 주소를 차례로 넣어 바뀌는지 확인하고, 끝나면 원래 클립보드(텍스트·이미지 등 모든 형식)를 복원합니다. 바뀐 값은 공격자 주소로 추정됩니다. 테스트 중 약 8초간 클립보드가 바뀝니다.
- **정적 점검**: 새 자동 실행 항목에 클립보드 접근 + 지갑 주소 정규식이 함께 있으면 critical. 브라우저 확장의 copy 이벤트 후킹 코드도 검사합니다.
- **개인정보**: 지갑 주소 형식인 값만 메모리에서 비교하며, 그 외 클립보드 내용은 저장·로그하지 않습니다. 화면에는 주소를 마스킹해 표시합니다.
- **한계**: 어떤 프로세스가 클립보드를 바꿨는지는 macOS 가 알려주지 않으므로, 자동 실행 항목·확장·프로세스 탐지 결과와 함께 판단해야 합니다.

### 악성 브라우저 확장 탐지 — macOS

대상: Chrome, Chrome Beta, Chromium, Edge, Brave, Arc, Vivaldi, Whale, Opera (모든 프로필), Firefox

**위험도 = 악성 징후 + 권한 ÷ 3** (critical ≥ 60, high ≥ 35, medium ≥ 15). 권한이 강한 정상 확장(지갑, VPN, 보안 플러그인)은 권한만으로 medium 을 넘지 않습니다.

- **악성 징후**: Chrome Safe Browsing 차단, 웹스토어 위반·게시 중단, 파일 변조(무결성 실패), 압축해제·`--load-extension`·사이드로드·정책 강제 설치, 자체 업데이트 서버, 코드 패턴(키로거/폼 그래버, 쿠키 일괄 수집·전송, 원격 코드 eval, 원격 스크립트 주입, 다른 확장 비활성화, CSP 제거, 난독화, 지갑 확장 ID 목록, 클리퍼)
- **권한**: debugger, proxy, nativeMessaging, management, clipboardRead, cookies, 모든 사이트 접근, 검색엔진·새 탭 변경 등
- **공급망 공격 대응**: 업데이트 후 권한이 늘거나 새 악성 징후가 생기면 알림
- **강제 설치 경로**: `/Library/Managed Preferences` 의 강제 설치 정책, `External Extensions` 사이드로드 설정
- 설정: `trustedIds`(검토 완료, 알림 제외), `blockedIds` / `blocklistFile`(설치 시 항상 critical)

---

## API

Swagger UI: `http://localhost:<apiPort>/swagger/` — 스펙은 `api/openapi.yaml` (변경 후 `make generate`)

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/v1/health` | 서버 상태 |
| GET | `/api/v1/events` | 이벤트 목록 (`category`, `detector`, `limit`, `offset`) |
| POST | `/api/v1/events` | 이벤트 등록 (외부 연동용) |
| GET | `/api/v1/detectors` | 탐지기 상태 목록 |
| GET | `/api/v1/detectors/{name}` | 탐지기 상세 (현재 상태, 검사 대상) |
| GET | `/api/v1/detectors/{name}/runs` | 실행 이력 (`limit`, `offset`) |
| GET | `/api/v1/detectors/{name}/runs/{id}` | 실행 1건 상세 (당시 점검 항목) |
| POST | `/api/v1/clipboard/test` | 클립보드 카나리아 테스트 (macOS) |
| GET | `/api/v1/system/status` | 현재 CPU·메모리·디스크·상위 프로세스 |
| GET | `/api/v1/network/status` | 현재 네트워크 상태·프로세스별 연결·연결 목록 (LISTEN 제외 TCP, 최대 1000개) |
| GET | `/api/v1/firewall/status` | 방화벽 동작 여부와 설정 내역 (조회 시점에 수집) |
| POST | `/api/v1/firewall/open` | 시스템 설정 → 네트워크 → 방화벽 열기 (macOS, 서버가 실행 중인 Mac 에서 열림) |
| GET | `/api/v1/recording/status` | 화면·마이크·카메라 사용 현황, 장치, 녹화·원격 도구, 녹화 권한, 최근 사용 기록 |
| GET | `/api/v1/metrics` | 시계열 지표 (`names=cpu.usage,mem.used_pct,...`, `range=1h\|6h\|24h\|7d`) |

시계열 지표 이름: `cpu.usage`, `cpu.load1`, `mem.used_pct`, `mem.swap_used`, `disk.used_pct`, `net.rx_bps`, `net.tx_bps`, `net.established`, `net.external`, `net.latency_ms`

---

## 데이터

| 위치 | 내용 |
|---|---|
| `detector.db` (`events`) | 탐지 이벤트 |
| `detector.db` (`detect_state`) | 탐지기 기준선 (알려진 파일·포트·계정·확장, 로그 커서 등) |
| `detector.db` (`detect_runs`) | 탐지기 실행 이력과 당시 점검 항목 |
| `detector.db` (`metrics`) | 시계열 지표 (`metricsRetention` 지나면 자동 삭제) |
| `logs/` | 일자별 JSON 로그 |

**초기화**: 서버를 **종료한 뒤** `detector.db`, `detector.db-wal`, `detector.db-shm` 을 함께 삭제합니다. 다음 실행 때 모든 탐지기가 기준선부터 다시 만듭니다. `build/`, `logs/` 는 언제 지워도 됩니다.

---

## UI 개발 (`web/`)

React 19 + Vite 7 + TypeScript + Tailwind CSS 4. 아이콘은 lucide-react.

```sh
make run        # 터미널 1: Go 서버
make dev-web    # 터미널 2: Vite 개발 서버 (핫 리로드) → http://localhost:5173/detector/
```

- 개발 서버는 `/api` 요청을 `web/.env.development` 의 **`VITE_PROXY_TARGET`** 으로 넘깁니다 → `config.toml` 의 `apiPort` 와 **포트를 맞춰야** 합니다.
- `web/.env.production`: `VITE_APP_BASE_URL="/detector"` (서버의 `WebPrefix` 와 같아야 함), `VITE_API_BASE_URL="/api/v1"`
- 빌드 결과(`web/dist`)는 해시 없는 고정 파일명이며, `make build` 가 바이너리에 포함합니다.
- 메뉴 추가: `web/src/menus.tsx` (사이드바와 라우트에 함께 반영) · 문구/언어 추가: `web/src/i18n/messages.ts`

---

## 문제 해결

| 증상 | 원인 / 해결 |
|---|---|
| UI 대신 "웹 UI 가 빌드에 포함되지 않았습니다" | `NOWEB=1` 로 빌드했거나 UI 복사 전 빌드됨 → `make build` |
| `make dev-web` 화면에서 API 오류 (500) | `VITE_PROXY_TARGET` 포트가 `apiPort` 와 다름 → `web/.env.development` 수정 후 개발 서버 재시작 |
| 탐지 기록/기준선이 사라짐 | 루트가 아닌 곳에서 실행해 새 DB 가 생김 → 루트에서 실행 |
| 녹화 감시 "TCC.db 읽기 불가" | 전체 디스크 접근 권한 필요 → 시스템 설정 → 개인정보 보호 및 보안 → 전체 디스크 접근 권한에 detector(또는 실행한 터미널) 추가 후 재시작 |
| 클립보드 탐지기 경고 "root 로 실행 중" | 클립보드는 로그인 사용자 세션에 속함 → 사용자 권한으로 실행 |
| 일부 파일이 "읽기 불가" | 권한 부족 → root 로 실행하면 내용까지 비교 |
