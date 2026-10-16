package handler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"detector/api"
	"detector/internal/detect"
)

func (h *Handler) GetSystemStatus(_ context.Context, _ api.GetSystemStatusRequestObject) (api.GetSystemStatusResponseObject, error) {
	v, _ := h.detect.Snapshot("resources")
	s, ok := v.(detect.SystemSnapshot)
	if !ok {
		return api.GetSystemStatus404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{
			Message: "system status not available yet (detect.resources disabled or first run pending)"}}, nil
	}
	out := api.GetSystemStatus200JSONResponse{
		At: s.At.In(h.loc),
		Cpu: api.CpuStat{UsagePct: s.CPU.UsagePct, UserPct: s.CPU.UserPct, SystemPct: s.CPU.SystemPct,
			Load1: s.CPU.Load1, Load5: s.CPU.Load5, Load15: s.CPU.Load15, Cores: s.CPU.Cores},
		Memory: api.MemoryStat{Total: int64(s.Memory.Total), Used: int64(s.Memory.Used), UsedPct: s.Memory.UsedPct,
			Pressure: s.Memory.Pressure, SwapTotal: int64(s.Memory.SwapTotal), SwapUsed: int64(s.Memory.SwapUsed)},
		Disks:  []api.DiskUsage{},
		TopCpu: h.procUsage(s.TopCPU),
		TopMem: h.procUsage(s.TopMem),
	}
	for _, d := range s.Disks {
		out.Disks = append(out.Disks, api.DiskUsage{Mount: d.Mount, Total: int64(d.Total), Used: int64(d.Used), Free: int64(d.Free), UsedPct: d.UsedPct})
	}
	return out, nil
}

func (h *Handler) procUsage(ps []detect.ProcStat) []api.ProcUsage {
	out := make([]api.ProcUsage, 0, len(ps))
	for _, p := range ps {
		u := api.ProcUsage{Pid: p.PID, Name: p.Name, Exe: p.Exe, User: p.User, CpuPct: p.CPUPct, Rss: int64(p.RSS)}
		if !p.HighSince.IsZero() {
			t := p.HighSince.In(h.loc)
			u.HighSince = &t
		}
		out = append(out, u)
	}
	return out
}

func (h *Handler) GetNetworkStatus(_ context.Context, _ api.GetNetworkStatusRequestObject) (api.GetNetworkStatusResponseObject, error) {
	v, _ := h.detect.Snapshot("network")
	s, ok := v.(detect.NetworkSnapshot)
	if !ok {
		return api.GetNetworkStatus404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{
			Message: "network status not available yet (detect.network disabled or first run pending)"}}, nil
	}
	out := api.GetNetworkStatus200JSONResponse{
		At: s.At.In(h.loc), Gateway: s.Gateway, GatewayMac: s.GatewayMAC, Interface: s.Interface,
		Dns: nonNil(s.DNS), Proxies: nonNil(s.Proxies),
		Internet:    api.InternetProbe{Reachable: s.Internet.Reachable, LatencyMs: s.Internet.LatencyMs, Target: s.Internet.Target},
		RxBps:       s.RxBps,
		TxBps:       s.TxBps,
		Established: s.Established,
		External:    s.External,
		Interfaces:  []api.NetInterface{},
		Processes:   []api.ProcConnections{},
		Connections: []api.NetConnection{},
	}
	if s.Internet.Error != "" {
		out.Internet.Error = &s.Internet.Error
	}
	for _, i := range s.Interfaces {
		if !i.Up || len(i.Addrs) == 0 {
			continue
		}
		out.Interfaces = append(out.Interfaces, api.NetInterface{Name: i.Name, Up: i.Up, Addrs: i.Addrs, RxBps: i.RxBps, TxBps: i.TxBps})
	}
	for _, p := range s.Processes {
		out.Processes = append(out.Processes, api.ProcConnections{
			Pid: p.PID, Name: p.Name, Exe: p.Exe, Conns: p.Conns, External: p.External, Hosts: p.Hosts, SynSent: p.SynSent,
			Ports: nonNilInts(p.Ports), Sample: nonNil(p.Sample), TxBytes: int64(p.TxBytes), RxBytes: int64(p.RxBytes), Flags: nonNil(p.Flags),
		})
	}
	for _, c := range s.Connections {
		out.Connections = append(out.Connections, api.NetConnection{
			Local: c.Local, Remote: c.Remote, RemotePort: c.RemotePort, Scope: c.Scope, State: c.State,
			Pid: c.PID, Process: c.Process, TxBytes: int64(c.TxBytes), RxBytes: int64(c.RxBytes),
		})
	}
	return out, nil
}

var metricRanges = map[api.GetMetricsParamsRange]time.Duration{
	"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
}

func (h *Handler) GetMetrics(ctx context.Context, req api.GetMetricsRequestObject) (api.GetMetricsResponseObject, error) {
	rng := api.GetMetricsParamsRange("1h")
	if req.Params.Range != nil {
		rng = *req.Params.Range
	}
	window, ok := metricRanges[rng]
	if !ok {
		return api.GetMetrics400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: fmt.Sprintf("invalid range %q", rng)}}, nil
	}
	var names []string
	for _, n := range strings.Split(req.Params.Names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 || len(names) > 20 {
		return api.GetMetrics400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: "names: 1..20 metric names required"}}, nil
	}
	series, err := h.detect.QueryMetrics(ctx, names, window, 240)
	if err != nil {
		return nil, err
	}
	out := api.GetMetrics200JSONResponse{Range: string(rng), Items: make([]api.MetricSeries, 0, len(series))}
	for _, s := range series {
		ms := api.MetricSeries{Name: s.Name, Points: make([]api.MetricPoint, 0, len(s.Points))}
		for _, p := range s.Points {
			ms.Points = append(ms.Points, api.MetricPoint{T: p.At.In(h.loc), V: p.Value})
		}
		out.Items = append(out.Items, ms)
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilInts(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

func (h *Handler) GetFirewallStatus(ctx context.Context, _ api.GetFirewallStatusRequestObject) (api.GetFirewallStatusResponseObject, error) {
	s, err := detect.CollectFirewall(ctx)
	if err != nil {
		return nil, err
	}
	out := api.GetFirewallStatus200JSONResponse{At: s.At.In(h.loc), Platform: s.Platform, Active: s.Active, Components: []api.FirewallComponent{}}
	for _, c := range s.Components {
		ac := api.FirewallComponent{Id: c.ID, Name: c.Name, Kind: c.Kind, State: c.State,
			Settings: []api.FirewallSetting{}, Rules: []api.FirewallRule{}, Files: []api.FirewallFile{}}
		if c.Detail != "" {
			ac.Detail = &c.Detail
		}
		for _, x := range c.Settings {
			st := api.FirewallSetting{Name: x.Name, Value: x.Value, Status: x.Status}
			if x.Note != "" {
				st.Note = &x.Note
			}
			ac.Settings = append(ac.Settings, st)
		}
		for _, r := range c.Rules {
			ar := api.FirewallRule{Target: r.Target, Action: r.Action, Warn: r.Warn}
			if r.Note != "" {
				ar.Note = &r.Note
			}
			ac.Rules = append(ac.Rules, ar)
		}
		for _, f := range c.Files {
			ac.Files = append(ac.Files, api.FirewallFile{Path: f.Path, Content: f.Content})
		}
		out.Components = append(out.Components, ac)
	}
	return out, nil
}
