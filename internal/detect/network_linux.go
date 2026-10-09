package detect

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type netSampler struct{}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

func exeUnsigned(string) (bool, bool) { return false, false }

func sampleNetwork(context.Context, *netSampler) (netRaw, error) {
	var raw netRaw

	// default route from /proc/net/route (destination 00000000)
	if f, err := os.Open("/proc/net/route"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 3 && fs[1] == "00000000" {
				if b, err := hex.DecodeString(fs[2]); err == nil && len(b) == 4 {
					raw.Gateway = net.IPv4(b[3], b[2], b[1], b[0]).String()
					raw.Interface = fs[0]
				}
				break
			}
		}
		f.Close()
	}
	if raw.Gateway != "" {
		_ = eachLine("/proc/net/arp", func(fs []string) {
			if len(fs) >= 4 && fs[0] == raw.Gateway && fs[3] != "00:00:00:00:00:00" {
				raw.GatewayMAC = strings.ToLower(fs[3])
			}
		})
	}

	resolv := "/etc/resolv.conf"
	raw.DNS = nameservers(resolv)
	if len(raw.DNS) == 1 && raw.DNS[0] == "127.0.0.53" {
		if up := nameservers("/run/systemd/resolve/resolv.conf"); len(up) > 0 {
			raw.DNS = up // systemd-resolved stub: report the real upstreams
		}
	}

	_ = eachLine("/etc/environment", func(fs []string) {
		if len(fs) == 0 {
			return
		}
		k, v, ok := strings.Cut(fs[0], "=")
		if ok && strings.HasSuffix(strings.ToLower(k), "_proxy") && !strings.EqualFold(k, "no_proxy") {
			raw.Proxies = append(raw.Proxies, k+" "+strings.Trim(v, `"'`))
		}
	})

	counters := map[string][2]uint64{}
	_ = eachLine("/proc/net/dev", func(fs []string) {
		if len(fs) < 10 || !strings.HasSuffix(fs[0], ":") {
			return
		}
		rx, _ := strconv.ParseUint(fs[1], 10, 64)
		tx, _ := strconv.ParseUint(fs[9], 10, 64)
		counters[strings.TrimSuffix(fs[0], ":")] = [2]uint64{rx, tx}
	})
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		st := IfaceStat{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				st.Addrs = append(st.Addrs, a.String())
			}
		}
		c := counters[ifc.Name]
		st.RxBytes, st.TxBytes = c[0], c[1]
		raw.Interfaces = append(raw.Interfaces, st)
	}

	conns := map[string]NetConn{} // inode -> conn
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		readProcConns(p, conns)
	}
	owners := socketOwners(listenersFromConns(conns))
	for inode, c := range conns {
		if pid, ok := owners[inode]; ok {
			c.PID = pid
			c.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
				c.Process = strings.TrimSpace(string(comm))
			} else if c.Exe != "" {
				c.Process = filepath.Base(c.Exe)
			}
		}
		raw.Conns = append(raw.Conns, c)
	}
	return raw, nil
}

func readProcConns(path string, out map[string]NetConn) {
	_ = eachLine(path, func(fs []string) {
		if len(fs) < 10 || fs[0] == "sl" {
			return
		}
		state := tcpStates[fs[3]]
		if state == "" || state == "LISTEN" {
			return
		}
		laddr, lport, ok1 := decodeProcAddr(fs[1])
		raddr, rport, ok2 := decodeProcAddr(fs[2])
		if !ok1 || !ok2 {
			return
		}
		out[fs[9]] = NetConn{Local: hostPort(laddr, lport), Remote: hostPort(raddr, rport), RemoteIP: raddr, RemotePort: rport, State: state}
	})
}

// listenersFromConns adapts the inode set for socketOwners.
func listenersFromConns(conns map[string]NetConn) map[string]listener {
	m := make(map[string]listener, len(conns))
	for k := range conns {
		m[k] = listener{}
	}
	return m
}

func nameservers(path string) []string {
	var out []string
	_ = eachLine(path, func(fs []string) {
		if len(fs) >= 2 && fs[0] == "nameserver" {
			out = append(out, fs[1])
		}
	})
	return out
}

func eachLine(path string, fn func([]string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Fields(line))
	}
	return sc.Err()
}

func hostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}
