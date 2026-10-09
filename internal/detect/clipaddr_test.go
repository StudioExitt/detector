package detect

import (
	"strings"
	"testing"
	"time"
)

func TestParseCryptoAddr(t *testing.T) {
	tests := map[string]string{
		"0x52908400098527886E0F7030069857D2E4169EE7":                        "evm",
		"  ethereum:0x52908400098527886E0F7030069857D2E4169EE7@1?value=1\n": "evm",
		"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq":                        "btc",
		"bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2?amount=0.1":             "btc",
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy":                                "btc",
		"ltc1qg82tyzhh3d6n7mmc7c3jtrfk7z5p6k0yjk6ywy":                       "ltc",
		"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t":                                "tron",
		"rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh":                                "xrp",
		"DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L":                                "doge",
		"So11111111111111111111111111111111111111112":                       "sol",
		"EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q2":                  "ton",
	}
	for in, chain := range tests {
		a := parseCryptoAddr(in)
		if a == nil || a.Chain != chain {
			t.Errorf("%q: got %+v, want chain %s", in, a, chain)
		}
	}
	for _, in := range []string{
		"hello world", "https://example.com/0x52908400098527886E0F7030069857D2E4169EE7 x",
		"0x1234", "Supercalifragilisticexpialidociouswordstuff", "",
	} {
		if a := parseCryptoAddr(in); a != nil {
			t.Errorf("%q: unexpectedly parsed as %+v", in, a)
		}
	}
	// EVM checksum casing is not a different address
	a := parseCryptoAddr("0x52908400098527886E0F7030069857D2E4169EE7")
	b := parseCryptoAddr("0x52908400098527886e0f7030069857d2e4169ee7")
	if a.Norm != b.Norm {
		t.Error("evm addresses must compare case-insensitively")
	}
}

func TestLookalike(t *testing.T) {
	p, s := lookalike("0x5290aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9EE7", "0x5290bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9ee7")
	if p != 4 || s != 4 {
		t.Fatalf("got prefix %d suffix %d", p, s)
	}
}

func TestJudgeClipChange(t *testing.T) {
	now := time.Now()
	victim := parseCryptoAddr("0x52908400098527886E0F7030069857D2E4169EE7")
	attacker := parseCryptoAddr("0x5290aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9EE7")
	btc := parseCryptoAddr("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")

	prev := clipObservation{Count: 10, Addr: victim, At: now}
	cases := []struct {
		name string
		prev clipObservation
		cur  clipObservation
		want clipVerdict
	}{
		{"swap within window", prev, clipObservation{Count: 11, Addr: attacker, At: now.Add(120 * time.Millisecond)}, clipSwapped},
		{"user copies another address later", prev, clipObservation{Count: 11, Addr: attacker, At: now.Add(10 * time.Second)}, clipNone},
		{"different chain", prev, clipObservation{Count: 11, Addr: btc, At: now.Add(100 * time.Millisecond)}, clipNone},
		{"same address re-copied", prev, clipObservation{Count: 11, Addr: victim, At: now.Add(100 * time.Millisecond)}, clipNone},
		{"own canary write", prev, clipObservation{Count: 11, Addr: attacker, At: now.Add(100 * time.Millisecond), Self: true}, clipNone},
		{"two writes between polls", clipObservation{Count: 10, At: now}, clipObservation{Count: 12, Addr: attacker, At: now.Add(50 * time.Millisecond)}, clipRapidRewrite},
		{"first observation", clipObservation{}, clipObservation{Count: 5, Addr: attacker, At: now}, clipNone},
	}
	for _, c := range cases {
		if got := judgeClipChange(c.prev, c.cur, time.Second); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestJudgeCanaryChange(t *testing.T) {
	canary := "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
	if obs, ok := judgeCanaryChange("btc", canary, "1BvBMSrkmxw9fxfs229c08ua9zd4ckNVN2"); !ok {
		t.Errorf("malformed look-alike should count as swap: %s", obs)
	}
	if obs, ok := judgeCanaryChange("btc", canary, "my secret note"); ok || strings.Contains(obs, "secret") {
		t.Errorf("unrelated content must not be a swap nor echoed: %s", obs)
	}
	if _, ok := judgeCanaryChange("evm", "0x000000000000000000000000000000000000dEaD", "0x000000000000000000000000000000000000dead"); ok {
		t.Error("same address in different case is not a swap")
	}
}
