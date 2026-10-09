package detect

import (
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Platform-independent parsers, kept here so they are unit-tested on every OS.

// "Oct  2 17:00:00 host sshd[123]: msg" or "2026-10-02T17:00:00.1+09:00 host sshd[123]: msg"
var reSyslogLine = regexp.MustCompile(`^(?:\w{3}\s+\d+\s+[\d:]+|\S+)\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:\s+(.*)$`)

// parseSyslogAuth parses one syslog line from auth.log / secure.
func parseSyslogAuth(line string) (authEvent, bool) {
	m := reSyslogLine.FindStringSubmatch(line)
	if m == nil {
		return authEvent{}, false
	}
	return parseLinuxAuth(m[1], m[2])
}

func parseLinuxAuth(prog, msg string) (authEvent, bool) {
	switch prog {
	case "sshd", "sshd-session":
		return parseSSHD(msg)
	case "sudo":
		return parseSudo(msg)
	}
	return authEvent{}, false
}

// decodeProcAddr decodes "0100007F:0277" / 32-hex-digit IPv6 forms.
func decodeProcAddr(s string) (string, int, bool) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false
	}
	b, err := hex.DecodeString(host)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, false
	}
	// each 32-bit word is stored in host (little-endian) order
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip := net.IP(b)
	switch {
	case ip.Equal(net.IPv4zero):
		return "0.0.0.0", int(port), true
	case ip.Equal(net.IPv6zero):
		return "::", int(port), true
	}
	return ip.String(), int(port), true
}
