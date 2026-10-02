# Detector

해킹, 비정상 시스템 점유, 취약점 점검 등을 감시하는 서비스.

| 디렉토리 | 내용 |
|---|---|
| `server/` | Go 1.25 API 서버 (net/http + oapi-codegen, SQLite(modernc, no CGO), slog JSON 로그) |
| `web/` | React 19 + Vite 7 + TypeScript + Tailwind CSS 4 클라이언트 |

## server

```sh
cd server
make build-linux-amd64   # build/detector-linux-amd64
make build-linux-arm64   # build/detector-linux-arm64
make build-linux         # 둘 다
make run                 # go run ./cmd/detector -c config.toml
make generate            # api/openapi.yaml → api/api.gen.go

./build/detector -c config.toml      # 또는 -config config.toml
```

- 설정: `config.toml` (기본값: apiPort=8088, logLevel=info, timeZone=로컬)
- 로그: `[log] dir` 아래 `detector-YYYY-MM-DD.log` (JSON, 일자별)
- DB: SQLite WAL 모드 (`?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)`)
- API: `/api/v1/*`, Swagger UI: `/swagger/` (바이너리에 포함)
- API 변경 시 `api/openapi.yaml` 수정 후 `make generate`

### 침입 탐지 (`internal/detect`)

서버 기동 시 OS 에 맞는 탐지기가 주기적으로 실행되고, 결과는 events 테이블(`detector`, `rule` 포함)에 저장됩니다.
동작 상태는 `GET /api/v1/detectors` 또는 웹의 "탐지기 상태" 메뉴에서 확인합니다.

| 탐지기 | macOS | Linux | 주요 규칙 |
|---|---|---|---|
| auth | unified log (`opendirectoryd` 인증 실패, sshd, sudo) | `/var/log/auth.log`·`secure` tail → 없으면 journald | `auth.ssh_bruteforce`, `auth.ssh_success_after_failures`, `auth.ssh_new_source`, `auth.ssh_root_login`, `auth.local_bruteforce`, `auth.sudo_failures`, `auth.sudo_not_allowed` |
| fim | LaunchAgents/Daemons(+plist 프로그램 코드서명 검사), sudoers, pam.d, authorized_keys, 셸 rc, cron, hosts … | passwd/shadow/group, sudoers, cron, systemd, `ld.so.preload`, authorized_keys, 셸 rc … | `fim.added`, `fim.modified`, `fim.removed`, `fim.mode_changed` |
| listeners | `netstat -anv` (root 없이 PID 확인) | `/proc/net/tcp{,6}` + `/proc/*/fd` | `net.new_listener` |
| process | `ps` (+ 상대경로는 `lsof` 로 실제 경로 확인) | `/proc` (삭제된 실행파일 포함) | `proc.suspicious_path`, `proc.miner`, `proc.reverse_shell`, `proc.deleted_exe` |
| accounts | `dscl` (사용자, admin 그룹) | `/etc/passwd`, `/etc/group`(sudo/wheel), `/etc/shadow` | `account.added`, `account.admin_added`, `account.uid0`, `account.no_password` |
| posture | SIP, Gatekeeper, 방화벽/스텔스, FileVault, SSH·화면공유·ARD, 자동 로그인, 게스트, 보안 업데이트 | sshd(PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords), ASLR, SELinux/AppArmor | `posture.*` (처음엔 취약점 점검, 정상→취약 변화는 침입) |

| clipboard (macOS) | `NSPasteboard` 50ms 감시 (purego, no cgo) + 카나리아 테스트 | - | `clipboard.address_swapped`, `clipboard.rapid_rewrite`, `clipboard.canary_swapped` |
| extensions (macOS) | Chrome 계열 프로필별 Secure Preferences(설치 경로·웹스토어 판정·차단 사유) + manifest + JS 코드, Firefox extensions.json, Managed Preferences 강제 설치, External Extensions | - | `browser.ext_risky`, `browser.ext_new`, `browser.ext_perm_escalation`, `browser.ext_new_verdict`, `browser.ext_blocklisted`, `browser.ext_policy_install`, `browser.ext_sideload`, `proc.browser_load_extension` |

| resources | `top`·`vm_stat`·`sysctl`(메모리 압박/스왑)·`ps`·statfs | `/proc/stat`·`/proc/meminfo`·PSI·`/proc/<pid>/stat`·statfs | `res.cpu_hog`, `res.cpu_high`, `res.mem_pressure`, `res.mem_hog`, `res.disk_full`, `res.disk_growth` |
| network | `route`·`arp`·`scutil --dns/--proxy`·`netstat -ib/-anv`(소켓별 송수신량)·`codesign` | `/proc/net/route·arp·dev·tcp`, resolv.conf, /etc/environment | `net.suspicious_port`, `net.suspicious_process`, `net.unsigned_process`, `net.conn_flood`, `net.many_hosts`, `net.outbound_scan`, `net.large_upload`(macOS), `net.dns_changed`, `net.proxy_changed`, `net.gateway_mac_changed`, `net.offline` |

- 시계열 지표(`metrics` 테이블, 기본 7일 보관): `GET /api/v1/metrics?names=cpu.usage,mem.used_pct&range=1h|6h|24h|7d`
- 현재 상태: `GET /api/v1/system/status`, `GET /api/v1/network/status`
- 실행 이력: 계정·클립보드 탐지기는 정상 실행은 마지막 1건만, 탐지/오류가 있는 실행은 모두 보관

#### 클립보드 바꿔치기(clipper) 탐지 — macOS

- **실시간**: 복사된 지갑 주소(EVM/BTC/LTC/DOGE/TRON/XRP/XMR/TON/SOL)가 `swapWindow` 안에 같은 체인의 다른 주소로 바뀌면 critical. macOS 는 클립보드 변경 알림이 없어 클리퍼도 polling 하므로, 더 촘촘한 50ms polling 으로 원래 주소를 먼저 관찰함
- **카나리아 테스트**: `POST /api/v1/clipboard/test` (웹: 탐지기 상태 → 클립보드 감시 → 테스트 실행). 공개 미끼 주소를 넣고 바뀌는지 확인 후 원래 클립보드(모든 형식)를 복원. 바뀐 값 = 공격자 주소로 추정
- **정적 점검**: 새 LaunchAgent/Daemon 의 실행 파일·스크립트에 클립보드 접근 + 지갑 주소 정규식이 함께 있으면 critical (`fim.added`), 브라우저 확장의 클립보드 권한 / copy 이벤트 후킹 코드 점검
- 사용자 세션에서 실행해야 함 (root LaunchDaemon 은 사용자 클립보드에 접근 불가). 주소 외 클립보드 내용은 저장·로그하지 않음
- 한계: 어떤 프로세스가 클립보드를 바꿨는지는 macOS 가 제공하지 않음 → 자동 실행 항목·확장·프로세스 탐지 결과와 함께 판단

#### 악성 브라우저 확장 탐지 — macOS

위험도 = **악성 징후** + **권한**÷3 (critical ≥ 60, high ≥ 35, medium ≥ 15). 권한이 강한 정상 확장(지갑·VPN·보안 플러그인)은 권한만으로 medium 을 넘지 않음.
- 악성 징후: Chrome Safe Browsing 차단, 웹스토어 위반/게시중단(`cws-info`), 무결성 실패(파일 변조), 압축해제·`--load-extension`·사이드로드·정책 강제 설치, 자체 업데이트 서버, 코드 패턴(키로거/폼 그래버, 쿠키 일괄 수집+전송, 원격 코드 eval, 원격 스크립트 주입, 다른 확장 비활성화, CSP 제거, 난독화, 지갑 확장 ID 목록, 클리퍼)
- 권한: debugger, proxy, nativeMessaging, management, clipboardRead, cookies, 모든 사이트 접근, 검색엔진/새 탭 변경 등
- 업데이트로 권한이 늘거나 새 악성 징후가 생기면 `browser.ext_perm_escalation` / `browser.ext_new_verdict` (개발자 계정 탈취형 공급망 공격 대응)

- 첫 실행 시 기준선(baseline)을 `detect_state` 테이블에 저장하고 이후 변화만 보고합니다. 재시작해도 기준선과 중복 억제(cooldown)는 유지됩니다.
- **root 실행 권장**: 일반 사용자로 실행하면 다른 사용자 프로세스의 실행 경로, root 전용 파일 내용(크기/수정시각만 비교), Linux auth.log 를 읽지 못할 수 있습니다.

## web

```sh
cd web
npm install
npm run dev     # http://localhost:5173/detector/  (/api 는 VITE_PROXY_TARGET 으로 proxy)
npm run build   # vite build --mode production → .env.production 사용, dist/ (해시 없는 파일명)
```

- `.env*`: `VITE_APP_BASE_URL`(라우터/asset base), `VITE_API_BASE_URL`(API 주소)
- 메뉴 추가: `src/menus.tsx` 에 항목 추가 (사이드바 + 라우트 자동 반영)
- 언어 추가: `src/i18n/messages.ts`
- 테마/언어/사이드바 상태는 localStorage(`detector.*`)에 저장
