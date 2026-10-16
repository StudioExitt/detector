package detect

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"
)

// OpenFirewallSettings has no common GUI on Linux.
func OpenFirewallSettings(context.Context) error { return ErrUnavailable }

func collectFirewall(ctx context.Context) ([]FirewallComponent, error) {
	var comps []FirewallComponent
	for _, c := range []FirewallComponent{ufwComponent(ctx), firewalldComponent(ctx), nftComponent(ctx), iptablesComponent(ctx)} {
		if c.ID != "" {
			comps = append(comps, c)
		}
	}
	return comps, nil
}

func installed(name string) bool {
	for _, d := range []string{"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"} {
		if _, err := os.Stat(d + name); err == nil {
			return true
		}
	}
	return false
}

func permissionNote(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "root") || strings.Contains(msg, "ermission") || strings.Contains(msg, "privilege") {
		return "규칙 조회는 root 권한 필요"
	}
	return firstLine(msg)
}

// ufw: `ufw status verbose` needs root; ENABLED in /etc/ufw/ufw.conf does not.
func ufwComponent(ctx context.Context) FirewallComponent {
	if !installed("ufw") {
		return FirewallComponent{}
	}
	c := FirewallComponent{ID: "ufw", Name: "UFW", Kind: "builtin", State: fwUnknown}
	_ = eachLine("/etc/ufw/ufw.conf", func(fs []string) {
		if len(fs) > 0 && strings.HasPrefix(fs[0], "ENABLED=") {
			if strings.Contains(strings.ToLower(fs[0]), "yes") {
				c.State = fwOn
			} else {
				c.State = fwOff
			}
		}
	})
	out, err := runCmd(ctx, 10*time.Second, "ufw", "status", "verbose")
	if err != nil {
		c.Detail = permissionNote(err)
		return c
	}
	parseUFW(out, &c)
	return c
}

func firewalldComponent(ctx context.Context) FirewallComponent {
	if !installed("firewall-cmd") {
		return FirewallComponent{}
	}
	c := FirewallComponent{ID: "firewalld", Name: "firewalld", Kind: "builtin", State: fwUnknown}
	st, err := runCmd(ctx, 10*time.Second, "firewall-cmd", "--state")
	switch {
	case strings.TrimSpace(st) == "running":
		c.State = fwOn
	case exitCode(err) == 252 || strings.Contains(st, "not running"):
		c.State = fwOff
		return c
	default:
		c.Detail = permissionNote(err)
		return c
	}
	out, err := runCmd(ctx, 10*time.Second, "firewall-cmd", "--list-all")
	if err != nil {
		c.Detail = permissionNote(err)
		return c
	}
	for line := range strings.Lines(out) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "target", "icmp-block-inversion", "masquerade":
			c.Settings = append(c.Settings, FirewallSetting{Name: k, Value: v, Status: CheckOK})
		case "services", "ports":
			for _, x := range strings.Fields(v) {
				c.Rules = append(c.Rules, FirewallRule{Target: k + " " + x, Action: "allow"})
			}
		case "rich rules":
			if v != "" {
				c.Rules = append(c.Rules, FirewallRule{Target: v, Action: "rule"})
			}
		}
	}
	return c
}

func nftComponent(ctx context.Context) FirewallComponent {
	if !installed("nft") {
		return FirewallComponent{}
	}
	c := FirewallComponent{ID: "nftables", Name: "nftables", Kind: "builtin", State: fwUnknown}
	out, err := runCmd(ctx, 10*time.Second, "nft", "list", "ruleset")
	if err != nil {
		c.Detail = permissionNote(err)
		if b, err := os.ReadFile("/etc/nftables.conf"); err == nil {
			c.Files = append(c.Files, FirewallFile{Path: "/etc/nftables.conf", Content: string(b)})
		}
		return c
	}
	c.State = fwOff
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if strings.Contains(t, "policy drop") {
			c.State = fwOn
		}
		if strings.HasSuffix(t, "accept") || strings.HasSuffix(t, "drop") || strings.HasSuffix(t, "reject") {
			action := "allow"
			if !strings.HasSuffix(t, "accept") {
				action = "block"
			}
			c.State = fwOn
			c.Rules = append(c.Rules, FirewallRule{Target: t, Action: action})
		}
	}
	c.Files = append(c.Files, FirewallFile{Path: "nft list ruleset", Content: out})
	return c
}

func iptablesComponent(ctx context.Context) FirewallComponent {
	if !installed("iptables") {
		return FirewallComponent{}
	}
	c := FirewallComponent{ID: "iptables", Name: "iptables", Kind: "builtin", State: fwUnknown}
	out, err := runCmd(ctx, 10*time.Second, "iptables", "-S")
	if err != nil {
		c.Detail = permissionNote(err)
		return c
	}
	c.State = fwOff
	for line := range strings.Lines(out) {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "-P "):
			f := strings.Fields(t)
			if len(f) == 3 {
				st := CheckOK
				if f[1] == "INPUT" && f[2] == "ACCEPT" {
					st = CheckWarn
				}
				if f[2] != "ACCEPT" {
					c.State = fwOn
				}
				c.Settings = append(c.Settings, FirewallSetting{Name: f[1] + " 기본 정책", Value: f[2], Status: st})
			}
		case strings.HasPrefix(t, "-A "):
			action := "rule"
			switch {
			case strings.Contains(t, "-j ACCEPT"):
				action = "allow"
			case strings.Contains(t, "-j DROP"), strings.Contains(t, "-j REJECT"):
				action = "block"
				c.State = fwOn
			}
			c.Rules = append(c.Rules, FirewallRule{Target: t, Action: action})
		}
	}
	return c
}
