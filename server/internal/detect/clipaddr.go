package detect

import (
	"regexp"
	"strings"
	"time"
)

// cryptoAddr is a clipboard value recognised as a wallet address.
type cryptoAddr struct {
	Chain string // evm, btc, ltc, doge, tron, xrp, xmr, ton, sol
	Raw   string // as copied (scheme / query stripped)
	Norm  string // comparison form (case-folded where the encoding is case-insensitive)
}

var addrPatterns = []struct {
	chain    string
	re       *regexp.Regexp
	foldCase bool
}{
	{"evm", regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`), true},
	{"btc", regexp.MustCompile(`^(?i:bc1|tb1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}$`), true},
	{"ltc", regexp.MustCompile(`^(?i:ltc1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}$`), true},
	{"btc", regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`), false},
	{"doge", regexp.MustCompile(`^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$`), false},
	{"ltc", regexp.MustCompile(`^[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$`), false},
	{"tron", regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`), false},
	{"xrp", regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{24,34}$`), false},
	{"xmr", regexp.MustCompile(`^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$`), false},
	{"ton", regexp.MustCompile(`^(?:EQ|UQ)[A-Za-z0-9_-]{46}$`), false},
	{"sol", regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`), false},
}

var reAddrScheme = regexp.MustCompile(`(?i)^(bitcoin|ethereum|litecoin|dogecoin|tron|solana|ripple|xrp|monero|ton):(//)?`)

// parseCryptoAddr recognises a single wallet address (optionally as a payment
// URI such as "ethereum:0x..@1?value=1"). Anything else returns nil.
func parseCryptoAddr(s string) *cryptoAddr {
	s = strings.TrimSpace(s)
	if len(s) < 25 || len(s) > 200 || strings.ContainsAny(s, " \t\r\n") {
		return nil
	}
	s = reAddrScheme.ReplaceAllString(s, "")
	if i := strings.IndexAny(s, "?@/"); i > 0 {
		s = s[:i]
	}
	for _, p := range addrPatterns {
		if !p.re.MatchString(s) {
			continue
		}
		if p.chain == "sol" && !looksRandomBase58(s) {
			return nil
		}
		norm := s
		if p.foldCase {
			norm = strings.ToLower(s)
		}
		return &cryptoAddr{Chain: p.chain, Raw: s, Norm: norm}
	}
	return nil
}

// looksRandomBase58 avoids treating long plain words as Solana addresses.
func looksRandomBase58(s string) bool {
	var upper, lower, digit bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// maskAddr shortens an address for display: 0x1234ab…9f3c
func maskAddr(s string) string {
	if len(s) <= 14 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

// lookalike returns how many leading / trailing characters two addresses share
// (case-insensitive, ignoring the chain prefix such as 0x / bc1 / T).
func lookalike(a, b string) (prefix, suffix int) {
	a, b = strings.ToLower(a), strings.ToLower(b)
	skip := 0
	for _, p := range []string{"0x", "bc1q", "bc1p", "bc1", "ltc1", "eq", "uq"} {
		if strings.HasPrefix(a, p) && strings.HasPrefix(b, p) {
			skip = len(p)
			break
		}
	}
	if skip == 0 && len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		skip = 1 // version / network character (T, r, 1, 3, D ...)
	}
	for i := skip; i < len(a) && i < len(b) && a[i] == b[i]; i++ {
		prefix++
	}
	for i := 1; i <= len(a)-skip && i <= len(b)-skip && a[len(a)-i] == b[len(b)-i]; i++ {
		suffix++
	}
	return prefix, suffix
}

// clipObservation is what the watcher remembers about the latest clipboard value.
type clipObservation struct {
	Count int
	Addr  *cryptoAddr
	At    time.Time
	Self  bool // written by the detector itself (canary test / restore)
}

type clipVerdict int

const (
	clipNone         clipVerdict = iota
	clipSwapped                  // address A replaced by a different address of the same chain within the window
	clipRapidRewrite             // several writes between two polls ending in an address
)

// judgeClipChange decides whether a clipboard change looks like a clipper.
func judgeClipChange(prev, cur clipObservation, window time.Duration) clipVerdict {
	if cur.Self || cur.Addr == nil || prev.Count == 0 {
		return clipNone
	}
	if prev.Addr != nil && prev.Addr.Chain == cur.Addr.Chain && prev.Addr.Norm != cur.Addr.Norm &&
		cur.At.Sub(prev.At) <= window {
		return clipSwapped
	}
	if cur.Count-prev.Count >= 2 {
		return clipRapidRewrite
	}
	return clipNone
}

// CanaryCheck is the outcome for one bait address of the clipboard test.
type CanaryCheck struct {
	Chain    string
	Canary   string
	Observed string // clipboard content after the change ("" when unchanged)
	Changed  bool
	Swapped  bool // replaced by a different address of the same chain
	AfterMs  int64
}

type CanaryResult struct {
	StartedAt  time.Time
	DurationMs int64
	Swapped    bool
	Restored   bool
	Note       string
	Checks     []CanaryCheck
}

// Bait addresses: well-known public addresses with valid checksums so that
// clippers which validate before replacing still react.
var canaryAddrs = []struct{ chain, addr string }{
	{"evm", "0x000000000000000000000000000000000000dEaD"},
	{"btc", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
	{"btc", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
	{"tron", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"},
	{"sol", "So11111111111111111111111111111111111111112"},
}

// judgeCanaryChange classifies what replaced a bait address. A look-alike
// value counts as a swap even when it is not a valid address (sloppy
// clippers). Unrelated content is not echoed back: it may be something the
// user copied during the test.
func judgeCanaryChange(chain, canary, observed string) (string, bool) {
	observed = strings.TrimSpace(observed)
	if a := parseCryptoAddr(observed); a != nil {
		c := parseCryptoAddr(canary)
		return a.Raw, a.Chain == chain && a.Norm != c.Norm
	}
	if len(observed) <= 120 && !strings.ContainsAny(observed, " \t\n") {
		if pre, suf := lookalike(canary, observed); pre >= 3 && suf >= 3 {
			return observed + " (형식이 깨진 유사 주소)", true
		}
	}
	return "(주소가 아닌 값으로 변경됨 — 테스트 중 사용자가 복사했을 수 있음)", false
}
