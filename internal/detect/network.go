package detect

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"detector/internal/config"
)

// NetworkSnapshot is the latest network state, served by GET /network/status.
type NetworkSnapshot struct {
	At          time.Time
	Gateway     string
	GatewayMAC  string
	Interface   string
	DNS         []string
	Proxies     []string
	Internet    ProbeResult
	Interfaces  []IfaceStat
	RxBps       float64
	TxBps       float64
	Established int
	External    int
	Processes   []ProcConns
	Connections []NetConn // external connections (capped)
}

type ProbeResult struct {
	Reachable bool
	LatencyMs float64
	Target    string
	Error     string
}

type IfaceStat struct {
	Name    string
	Up      bool
	Addrs   []string
	RxBytes uint64
	TxBytes uint64
	RxBps   float64
	TxBps   float64
}

type NetConn struct {
	Local      string
	Remote     string
	RemoteIP   string
	RemotePort int
	Scope      string // loopback / private / public
	State      string
	PID        int
	Process    string
	Exe        string
	RxBytes    uint64
	TxBytes    uint64
}

type ProcConns struct {
	PID      int
	Name     string
	Exe      string
	Conns    int // established, any scope
	External int // established to public addresses
	Hosts    int // distinct public remote IPs
	SynSent  int
	Ports    []int
	Sample   []string // a few remote endpoints
	TxBytes  uint64
	RxBytes  uint64
	Flags    []string // anomaly notes for the UI
}

// netRaw is what the platform collector returns.
type netRaw struct {
	Gateway, GatewayMAC, Interface string
	DNS                            []string
	Proxies                        []string
	Interfaces                     []IfaceStat
	Conns                          []NetConn
	HasBytes                       bool // per-connection byte counters available (macOS)
}

type uploadSample struct {
	at    time.Time
	bytes uint64
}

type networkDetector struct {
	cfg     config.NetworkDetectConfig
	sampler *netSampler

	prevAt     time.Time
	prevIface  map[string][2]uint64 // name -> rx, tx
	prevConnTx map[string]uint64    // conn key -> tx bytes
	uploads    map[string][]uploadSample
	offline    int
}

func newNetworkDetector(cfg config.NetworkDetectConfig) Detector {
	return &networkDetector{cfg: cfg, sampler: &netSampler{}, prevIface: map[string][2]uint64{},
		prevConnTx: map[string]uint64{}, uploads: map[string][]uploadSample{}}
}

func (d *networkDetector) Name() string { return "network" }

type netBaseline struct {
	DNS     []string          `json:"dns"`
	Proxies []string          `json:"proxies"`
	GwMAC   map[string]string `json:"gwMac"` // iface|gateway -> MAC
}

func (d *networkDetector) Check(ctx context.Context, env *Env) (Report, error) {
	raw, err := sampleNetwork(ctx, d.sampler)
	if err != nil {
		return Report{}, err
	}
	now := time.Now()
	snap := NetworkSnapshot{At: now, Gateway: raw.Gateway, GatewayMAC: raw.GatewayMAC, Interface: raw.Interface, DNS: raw.DNS, Proxies: raw.Proxies}
	snap.Internet = d.probe(ctx)

	// interface throughput
	elapsed := now.Sub(d.prevAt).Seconds()
	for _, ifc := range raw.Interfaces {
		if p, ok := d.prevIface[ifc.Name]; ok && elapsed > 0 && ifc.RxBytes >= p[0] && ifc.TxBytes >= p[1] {
			ifc.RxBps = float64(ifc.RxBytes-p[0]) / elapsed
			ifc.TxBps = float64(ifc.TxBytes-p[1]) / elapsed
		}
		d.prevIface[ifc.Name] = [2]uint64{ifc.RxBytes, ifc.TxBytes}
		if !strings.HasPrefix(ifc.Name, "lo") {
			snap.RxBps += ifc.RxBps
			snap.TxBps += ifc.TxBps
		}
		snap.Interfaces = append(snap.Interfaces, ifc)
	}
	d.prevAt = now

	var findings []Finding
	findings = append(findings, d.connectionFindings(env, raw, &snap, now)...)
	cf, err := d.configFindings(ctx, env, raw, snap)
	if err != nil {
		return Report{}, err
	}
	findings = append(findings, cf...)

	if !snap.Internet.Reachable && snap.Internet.Target != "" {
		d.offline++
		if d.offline == 3 {
			findings = append(findings, Finding{
				Rule: "net.offline", Category: CategoryIntrusion, Severity: SevLow, Source: env.Host,
				Message: fmt.Sprintf("인터넷 연결 끊김 (%d회 연속 실패): %s", d.offline, snap.Internet.Error),
			})
		}
	} else {
		d.offline = 0
	}

	metrics := map[string]float64{
		"net.rx_bps":      snap.RxBps,
		"net.tx_bps":      snap.TxBps,
		"net.established": float64(snap.Established),
		"net.external":    float64(snap.External),
	}
	if snap.Internet.Reachable {
		metrics["net.latency_ms"] = snap.Internet.LatencyMs
	}

	inet := "끊김"
	if snap.Internet.Reachable {
		inet = fmt.Sprintf("정상 %.0fms", snap.Internet.LatencyMs)
	} else if snap.Internet.Target == "" {
		inet = "점검 안 함"
	}
	return Report{
		Findings: findings,
		Summary: fmt.Sprintf("인터넷 %s · 연결 %d (외부 %d, 프로세스 %d) · ↓%s/s ↑%s/s",
			inet, snap.Established, snap.External, len(snap.Processes), humanBytes(uint64(snap.RxBps)), humanBytes(uint64(snap.TxBps))),
		Checks:   d.checks(snap),
		Metrics:  metrics,
		Snapshot: snap,
	}, nil
}

func (d *networkDetector) probe(ctx context.Context) ProbeResult {
	var lastErr string
	for _, t := range d.cfg.ProbeTargets {
		start := time.Now()
		var dialer net.Dialer
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := dialer.DialContext(cctx, "tcp", t)
		cancel()
		if err == nil {
			c.Close()
			return ProbeResult{Reachable: true, LatencyMs: float64(time.Since(start).Microseconds()) / 1000, Target: t}
		}
		lastErr = err.Error()
	}
	if len(d.cfg.ProbeTargets) == 0 {
		return ProbeResult{}
	}
	return ProbeResult{Target: strings.Join(d.cfg.ProbeTargets, ", "), Error: lastErr}
}

// ipScope classifies an address: loopback, private (RFC1918, ULA, link-local,
// CGNAT 100.64/10 used by Tailscale etc.) or public.
func ipScope(s string) string {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return "unknown"
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsUnspecified():
		return "private"
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return "private"
	}
	return "public"
}

func (d *networkDetector) connectionFindings(env *Env, raw netRaw, snap *NetworkSnapshot, now time.Time) []Finding {
	var findings []Finding
	byProc := map[string]*ProcConns{}
	hosts := map[string]map[string]bool{}
	liveConn := map[string]bool{}

	for _, c := range raw.Conns {
		c.Scope = ipScope(c.RemoteIP)
		pk := fmt.Sprintf("%d|%s", c.PID, c.Exe)
		pc, ok := byProc[pk]
		if !ok {
			pc = &ProcConns{PID: c.PID, Name: c.Process, Exe: c.Exe}
			byProc[pk] = pc
			hosts[pk] = map[string]bool{}
		}
		if c.State == "SYN_SENT" {
			pc.SynSent++
		}
		if c.State != "ESTABLISHED" {
			continue
		}
		snap.Established++
		pc.Conns++
		pc.RxBytes += c.RxBytes
		pc.TxBytes += c.TxBytes
		if c.Scope != "public" {
			continue
		}
		snap.External++
		pc.External++
		hosts[pk][c.RemoteIP] = true
		if !slices.Contains(pc.Ports, c.RemotePort) {
			pc.Ports = append(pc.Ports, c.RemotePort)
		}
		if len(pc.Sample) < 3 {
			pc.Sample = append(pc.Sample, c.Remote)
		}
		if len(snap.Connections) < 300 {
			snap.Connections = append(snap.Connections, c)
		}

		who := fmt.Sprintf("%s (pid %d) → %s", orNone(c.Process), c.PID, c.Remote)
		if slices.Contains(d.cfg.SuspiciousPorts, c.RemotePort) {
			pc.Flags = append(pc.Flags, fmt.Sprintf("의심 포트 %d", c.RemotePort))
			findings = append(findings, Finding{
				Rule: "net.suspicious_port", Category: CategoryIntrusion, Severity: SevHigh, Source: c.Remote, Key: pk + "|" + c.Remote,
				Message: fmt.Sprintf("의심 포트(%d: %s)로 외부 연결: %s — %s", c.RemotePort, portHint(c.RemotePort), who, orNone(c.Exe)),
			})
		}
		if inSuspiciousDir(c.Exe) || strings.Contains(c.Exe, "/.") {
			findings = append(findings, Finding{
				Rule: "net.suspicious_process", Category: CategoryIntrusion, Severity: SevHigh, Source: orNone(c.Exe), Key: pk,
				Message: fmt.Sprintf("임시/숨김 경로의 프로그램이 외부와 통신: %s — %s", who, c.Exe),
			})
		}

		// upload volume (macOS exposes per-socket byte counters)
		if raw.HasBytes {
			ck := fmt.Sprintf("%s|%s|%d", c.Local, c.Remote, c.PID)
			liveConn[ck] = true
			if prev, ok := d.prevConnTx[ck]; ok && c.TxBytes > prev {
				d.uploads[pk] = append(d.uploads[pk], uploadSample{now, c.TxBytes - prev})
			}
			d.prevConnTx[ck] = c.TxBytes
		}
	}
	for k := range d.prevConnTx {
		if !liveConn[k] {
			delete(d.prevConnTx, k)
		}
	}

	for pk, pc := range byProc {
		pc.Hosts = len(hosts[pk])
		sort.Ints(pc.Ports)
		who := fmt.Sprintf("%s (pid %d)", orNone(pc.Name), pc.PID)
		if pc.Conns >= d.cfg.MaxConnsPerProcess {
			pc.Flags = append(pc.Flags, "대량 연결")
			findings = append(findings, Finding{
				Rule: "net.conn_flood", Category: CategoryIntrusion, Severity: SevMedium, Source: orNone(pc.Exe), Key: pk,
				Message: fmt.Sprintf("단일 프로세스의 연결 %d개: %s — DDoS 봇/프록시 악용 의심", pc.Conns, who),
			})
		}
		if pc.Hosts >= d.cfg.MaxRemoteHosts {
			pc.Flags = append(pc.Flags, "다수 호스트")
			findings = append(findings, Finding{
				Rule: "net.many_hosts", Category: CategoryIntrusion, Severity: SevHigh, Source: orNone(pc.Exe), Key: pk,
				Message: fmt.Sprintf("단일 프로세스가 외부 호스트 %d곳과 동시 연결: %s — 스캔/봇넷 의심", pc.Hosts, who),
			})
		}
		if pc.SynSent >= 50 {
			pc.Flags = append(pc.Flags, "아웃바운드 스캔")
			findings = append(findings, Finding{
				Rule: "net.outbound_scan", Category: CategoryIntrusion, Severity: SevHigh, Source: orNone(pc.Exe), Key: pk,
				Message: fmt.Sprintf("응답 없는 연결 시도(SYN_SENT) %d개: %s — 포트 스캔/웜 전파 의심", pc.SynSent, who),
			})
		}
		// unsigned binaries talking to the internet (macOS)
		if pc.External > 0 && pc.Exe != "" && !isSystemExe(pc.Exe) {
			if unsigned, known := exeUnsigned(pc.Exe); known && unsigned {
				pc.Flags = append(pc.Flags, "서명 없음")
				findings = append(findings, Finding{
					Rule: "net.unsigned_process", Category: CategoryIntrusion, Severity: SevMedium, Source: pc.Exe, Key: pc.Exe,
					Message: fmt.Sprintf("코드 서명 없는 프로그램이 외부와 통신: %s → %s — %s", who, strings.Join(pc.Sample, ", "), pc.Exe),
				})
			}
		}
		// upload volume within 10 minutes
		var sum uint64
		kept := d.uploads[pk][:0]
		for _, u := range d.uploads[pk] {
			if now.Sub(u.at) <= 10*time.Minute {
				kept = append(kept, u)
				sum += u.bytes
			}
		}
		d.uploads[pk] = kept
		if mb := float64(sum) / (1 << 20); mb >= d.cfg.UploadMB && !isSystemExe(pc.Exe) {
			pc.Flags = append(pc.Flags, "대용량 업로드")
			findings = append(findings, Finding{
				Rule: "net.large_upload", Category: CategoryIntrusion, Severity: SevMedium, Source: orNone(pc.Exe), Key: pk,
				Message: fmt.Sprintf("10분간 %.0f MB 업로드: %s → %s — 데이터 유출 여부 확인", mb, who, strings.Join(pc.Sample, ", ")),
			})
		}
		if pc.Conns > 0 || pc.SynSent > 0 {
			snap.Processes = append(snap.Processes, *pc)
		}
	}
	for pk := range d.uploads {
		if _, ok := byProc[pk]; !ok {
			delete(d.uploads, pk)
		}
	}
	sort.Slice(snap.Processes, func(i, j int) bool {
		a, b := snap.Processes[i], snap.Processes[j]
		if len(a.Flags) != len(b.Flags) {
			return len(a.Flags) > len(b.Flags)
		}
		if a.External != b.External {
			return a.External > b.External
		}
		return a.Conns > b.Conns
	})
	return findings
}

func (d *networkDetector) configFindings(ctx context.Context, env *Env, raw netRaw, snap NetworkSnapshot) ([]Finding, error) {
	var base netBaseline
	found, err := env.State.Load(ctx, "baseline", &base)
	if err != nil {
		return nil, err
	}
	if base.GwMAC == nil {
		base.GwMAC = map[string]string{}
	}
	var findings []Finding

	dns := slices.Clone(raw.DNS)
	sort.Strings(dns)
	if found && !slices.Equal(dns, base.DNS) && len(dns) > 0 {
		findings = append(findings, Finding{
			Rule: "net.dns_changed", Category: CategoryIntrusion, Severity: SevMedium, Source: env.Host, Key: strings.Join(dns, ","),
			Message: fmt.Sprintf("DNS 서버 변경: %s → %s — VPN/네트워크 전환이 아니라면 DNS 하이재킹 의심",
				orNone(strings.Join(base.DNS, ", ")), strings.Join(dns, ", ")),
		})
	}

	proxies := slices.Clone(raw.Proxies)
	sort.Strings(proxies)
	switch {
	case !found && len(proxies) > 0:
		findings = append(findings, Finding{
			Rule: "net.proxy_set", Category: CategoryVulnScan, Severity: SevMedium, Source: env.Host, Key: strings.Join(proxies, ","),
			Message: "시스템 프록시가 설정되어 있음 (모든 웹 트래픽이 경유): " + strings.Join(proxies, ", "),
		})
	case found && !slices.Equal(proxies, base.Proxies) && len(proxies) > 0:
		findings = append(findings, Finding{
			Rule: "net.proxy_changed", Category: CategoryIntrusion, Severity: SevHigh, Source: env.Host, Key: strings.Join(proxies, ","),
			Message: fmt.Sprintf("시스템 프록시 설정 변경: %s → %s — 트래픽 가로채기(뱅킹 악성코드/애드웨어) 수법",
				orNone(strings.Join(base.Proxies, ", ")), strings.Join(proxies, ", ")),
		})
	}

	if raw.Gateway != "" && raw.GatewayMAC != "" {
		gk := raw.Interface + "|" + raw.Gateway
		if prev, ok := base.GwMAC[gk]; ok && !strings.EqualFold(prev, raw.GatewayMAC) {
			findings = append(findings, Finding{
				Rule: "net.gateway_mac_changed", Category: CategoryIntrusion, Severity: SevMedium, Source: raw.Gateway, Key: gk + "|" + raw.GatewayMAC,
				Message: fmt.Sprintf("게이트웨이 %s 의 MAC 이 %s → %s 로 변경 — 같은 IP 를 쓰는 다른 네트워크로 옮긴 게 아니라면 ARP 스푸핑(중간자 공격) 의심",
					raw.Gateway, prev, raw.GatewayMAC),
			})
		}
		base.GwMAC[gk] = raw.GatewayMAC
	}

	base.DNS, base.Proxies = dns, proxies
	return findings, env.State.Save(ctx, "baseline", base)
}

func (d *networkDetector) checks(s NetworkSnapshot) []Check {
	inet := Check{Name: "internet", Status: CheckOK, Detail: fmt.Sprintf("%s 연결 %.1fms", s.Internet.Target, s.Internet.LatencyMs)}
	switch {
	case s.Internet.Target == "":
		inet = Check{Name: "internet", Status: CheckOK, Detail: "점검 안 함 (probeTargets 비어 있음)"}
	case !s.Internet.Reachable:
		inet = Check{Name: "internet", Status: CheckFail, Detail: "연결 실패: " + s.Internet.Error}
	}
	gw := orNone(s.Gateway)
	if s.GatewayMAC != "" {
		gw += " (" + s.GatewayMAC + ")"
	}
	proxy := Check{Name: "proxy", Status: CheckOK, Detail: "없음"}
	if len(s.Proxies) > 0 {
		proxy = Check{Name: "proxy", Status: CheckWarn, Detail: strings.Join(s.Proxies, ", ")}
	}
	checks := []Check{
		inet,
		{Name: "gateway", Status: CheckOK, Detail: gw + " via " + orNone(s.Interface)},
		{Name: "dns", Status: CheckOK, Detail: orNone(strings.Join(s.DNS, ", "))},
		proxy,
	}
	for _, ifc := range s.Interfaces {
		if !ifc.Up || len(ifc.Addrs) == 0 || strings.HasPrefix(ifc.Name, "lo") {
			continue
		}
		checks = append(checks, Check{Name: "if " + ifc.Name, Status: CheckOK,
			Detail: fmt.Sprintf("%s — ↓%s/s ↑%s/s", strings.Join(ifc.Addrs, ", "), humanBytes(uint64(ifc.RxBps)), humanBytes(uint64(ifc.TxBps)))})
	}
	for i, p := range s.Processes {
		if i >= 15 {
			break
		}
		st := CheckOK
		note := ""
		if len(p.Flags) > 0 {
			st, note = CheckWarn, " ⚠ "+strings.Join(p.Flags, ", ")
		}
		checks = append(checks, Check{Name: fmt.Sprintf("proc %s (%d)", orNone(p.Name), p.PID), Status: st,
			Detail: fmt.Sprintf("연결 %d (외부 %d, 호스트 %d), 포트 %v%s — %s", p.Conns, p.External, p.Hosts, p.Ports, note, strings.Join(p.Sample, ", "))})
	}
	return checks
}

func portHint(p int) string {
	switch p {
	case 4444, 1337, 31337:
		return "백도어/Metasploit 기본 포트"
	case 6666, 6667, 6668, 6669, 6697:
		return "IRC (봇넷 C2)"
	case 9001, 9030, 9050, 9150:
		return "Tor"
	case 3333, 3334, 5555, 7777, 14433, 14444, 45560, 45700:
		return "채굴 풀(stratum)"
	}
	return "사용자 지정"
}
