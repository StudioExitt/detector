package detect

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type netSampler struct{}

var reArpMAC = regexp.MustCompile(`at ([0-9a-fA-F:]{11,17}) on`)

func sampleNetwork(ctx context.Context, _ *netSampler) (netRaw, error) {
	var raw netRaw
	raw.HasBytes = true

	if out, err := runCmd(ctx, 5*time.Second, "route", "-n", "get", "default"); err == nil {
		for line := range strings.Lines(out) {
			k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			switch k {
			case "gateway":
				raw.Gateway = strings.TrimSpace(v)
			case "interface":
				raw.Interface = strings.TrimSpace(v)
			}
		}
	}
	if raw.Gateway != "" && net.ParseIP(raw.Gateway) != nil {
		if out, err := runCmd(ctx, 5*time.Second, "arp", "-n", raw.Gateway); err == nil {
			if m := reArpMAC.FindStringSubmatch(out); m != nil {
				raw.GatewayMAC = strings.ToLower(m[1])
			}
		}
	}

	// default resolver (#1 of the non-scoped "DNS configuration" section)
	if out, err := runCmd(ctx, 5*time.Second, "scutil", "--dns"); err == nil {
		inFirst := false
	scan:
		for line := range strings.Lines(out) {
			t := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(t, "DNS configuration (for scoped"):
				break scan // the scoped section repeats "resolver #1"
			case t == "resolver #1":
				inFirst = true
			case strings.HasPrefix(t, "resolver #"):
				inFirst = false
			case inFirst && strings.HasPrefix(t, "nameserver["):
				if _, v, ok := strings.Cut(t, ":"); ok {
					raw.DNS = append(raw.DNS, strings.TrimSpace(v))
				}
			}
		}
	}

	raw.Proxies = darwinProxies(ctx)
	raw.Interfaces = darwinInterfaces(ctx)

	conns, err := darwinConns(ctx)
	if err != nil {
		return raw, err
	}
	raw.Conns = conns
	return raw, nil
}

func darwinProxies(ctx context.Context) []string {
	out, err := runCmd(ctx, 5*time.Second, "scutil", "--proxy")
	if err != nil {
		return nil
	}
	kv := map[string]string{}
	for line := range strings.Lines(out) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " : "); ok {
			kv[k] = v
		}
	}
	var out2 []string
	for _, p := range []string{"HTTP", "HTTPS", "SOCKS", "FTP", "RTSP"} {
		if kv[p+"Enable"] == "1" {
			out2 = append(out2, p+" "+kv[p+"Proxy"]+":"+kv[p+"Port"])
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" {
		out2 = append(out2, "PAC "+kv["ProxyAutoConfigURLString"])
	}
	if kv["ProxyAutoDiscoveryEnable"] == "1" {
		out2 = append(out2, "WPAD auto-discovery")
	}
	return out2
}

// darwinInterfaces: addresses from Go, byte counters from `netstat -ib`.
func darwinInterfaces(ctx context.Context) []IfaceStat {
	counters := map[string][2]uint64{}
	if out, err := runCmd(ctx, 5*time.Second, "netstat", "-ib"); err == nil {
		for line := range strings.Lines(out) {
			f := strings.Fields(line)
			// link rows: Name Mtu <Link#n> [Address] Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
			if len(f) < 10 || !strings.HasPrefix(f[2], "<Link#") {
				continue
			}
			n := len(f)
			ib, _ := strconv.ParseUint(f[n-5], 10, 64)
			ob, _ := strconv.ParseUint(f[n-2], 10, 64)
			counters[strings.TrimSuffix(f[0], "*")] = [2]uint64{ib, ob}
		}
	}
	ifs, _ := net.Interfaces()
	var out []IfaceStat
	for _, ifc := range ifs {
		st := IfaceStat{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				st.Addrs = append(st.Addrs, a.String())
			}
		}
		c := counters[ifc.Name]
		st.RxBytes, st.TxBytes = c[0], c[1]
		out = append(out, st)
	}
	return out
}

// darwinConns parses `netstat -anv -p tcp`, which includes per-socket byte
// counters and the owning pid without root.
func darwinConns(ctx context.Context) ([]NetConn, error) {
	out, err := runCmd(ctx, 20*time.Second, "netstat", "-anv", "-p", "tcp")
	if err != nil {
		return nil, err
	}
	procs, _ := darwinProcNames(ctx)
	col := map[string]int{}
	var conns []NetConn
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "Proto") {
			h := strings.NewReplacer("Local Address", "Local_Address", "Foreign Address", "Foreign_Address").Replace(line)
			for i, f := range strings.Fields(h) {
				if _, dup := col[f]; !dup {
					col[f] = i
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || f[5] == "LISTEN" || f[4] == "*.*" {
			continue
		}
		raddr, rport, ok := splitDarwinAddr(f[4])
		if !ok {
			continue
		}
		c := NetConn{Local: f[3], RemoteIP: raddr, RemotePort: rport, State: f[5]}
		c.Remote = hostPort(raddr, rport)
		get := func(name string) uint64 {
			if i, ok := col[name]; ok && i < len(f) {
				v, _ := strconv.ParseUint(f[i], 10, 64)
				return v
			}
			return 0
		}
		c.RxBytes, c.TxBytes = get("rxbytes"), get("txbytes")
		c.PID = int(get("pid"))
		if exe, ok := procs[c.PID]; ok {
			if !strings.HasPrefix(exe, "/") {
				exe = exeCache.resolve(ctx, c.PID, exe)
			}
			c.Exe, c.Process = exe, filepath.Base(exe)
		}
		conns = append(conns, c)
	}
	return conns, nil
}

func hostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

// exeUnsigned reports whether a binary fails code-signature verification.
// Results are cached per path and modification time.
var signCache sync.Map // path -> signCacheEntry

type signCacheEntry struct {
	mod      time.Time
	unsigned bool
}

func exeUnsigned(exe string) (unsigned bool, known bool) {
	fi, err := os.Stat(exe)
	if err != nil {
		return false, false
	}
	if c, ok := signCache.Load(exe); ok && c.(signCacheEntry).mod.Equal(fi.ModTime()) {
		return c.(signCacheEntry).unsigned, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = runCmd(ctx, 20*time.Second, "codesign", "--verify", exe)
	code := exitCode(err)
	if code != 0 && code != 1 {
		return false, false // timeout or unexpected failure: unknown
	}
	signCache.Store(exe, signCacheEntry{mod: fi.ModTime(), unsigned: code == 1})
	return code == 1, true
}
