package detect

import "testing"

func fwBase(state, stealth, autoSigned string, rules map[string]string, pfHash string) fwBaseline {
	return fwBaseline{
		States:   map[string]string{"alf": state},
		Settings: map[string]string{"alf|스텔스 모드": stealth, "alf|서명된 다운로드 소프트웨어 자동 허용": autoSigned},
		Rules:    rules,
		Files:    map[string]string{"/etc/pf.conf": pfHash},
		Names:    map[string]string{"alf": "애플리케이션 방화벽"},
	}
}

func TestFirewallChanges(t *testing.T) {
	prev := fwBase(fwOn, "켜짐", "꺼짐", map[string]string{"alf|/usr/sbin/cupsd": "allow"}, "aaa")
	cur := fwBase(fwOff, "꺼짐", "켜짐", map[string]string{"alf|/usr/sbin/cupsd": "allow", "alf|/usr/bin/python3": "allow"}, "bbb")
	snap := FirewallSnapshot{Components: []FirewallComponent{{ID: "alf", Rules: []FirewallRule{
		{Target: "/usr/sbin/cupsd", Action: "allow"},
		{Target: "/usr/bin/python3", Action: "allow", Warn: true, Note: "스크립트 인터프리터"},
	}}}}

	got := map[string][]Finding{}
	for _, f := range firewallChanges(prev, cur, snap, "host") {
		got[f.Rule] = append(got[f.Rule], f)
	}
	if len(got["firewall.disabled"]) != 1 || got["firewall.disabled"][0].Severity != SevHigh {
		t.Errorf("disabled: %+v", got["firewall.disabled"])
	}
	if s := got["firewall.setting_changed"]; len(s) != 2 || s[0].Severity != SevMedium || s[1].Severity != SevMedium {
		t.Errorf("stealth off and auto-allow on are both weakening: %+v", s)
	}
	if r := got["firewall.rule_added"]; len(r) != 1 || r[0].Severity != SevHigh {
		t.Errorf("interpreter allowed should be high: %+v", r)
	}
	if len(got["firewall.config_changed"]) != 1 {
		t.Errorf("pf.conf change: %+v", got["firewall.config_changed"])
	}
	if f := firewallChanges(cur, cur, snap, "host"); len(f) != 0 {
		t.Errorf("no change should produce no findings: %+v", f)
	}
}

func TestParseUFW(t *testing.T) {
	out := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     DENY IN     10.0.0.0/8
`
	var c FirewallComponent
	parseUFW(out, &c)
	if c.State != fwOn || len(c.Settings) != 2 || len(c.Rules) != 2 {
		t.Fatalf("got %+v", c)
	}
	if c.Rules[0].Action != "allow" || c.Rules[0].Note == "" || c.Rules[1].Action != "block" {
		t.Errorf("rules: %+v", c.Rules)
	}
}
