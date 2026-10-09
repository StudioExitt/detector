package detect

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// listAccounts uses Directory Services (dscl). Accounts starting with "_" and
// the built-in daemon/nobody accounts are system accounts and skipped, but
// UID 0 is always kept so hidden root-equivalent accounts are visible.
func listAccounts(ctx context.Context) (accountsSnapshot, error) {
	snap := accountsSnapshot{AdminGroup: "admin"}
	out, err := runCmd(ctx, 15*time.Second, "dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return snap, err
	}
	shells := map[string]string{}
	if sh, err := runCmd(ctx, 15*time.Second, "dscl", ".", "-list", "/Users", "UserShell"); err == nil {
		for line := range strings.Lines(sh) {
			if f := strings.Fields(line); len(f) == 2 {
				shells[f[0]] = f[1]
			}
		}
	}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		uid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		name := f[0]
		system := strings.HasPrefix(name, "_") || name == "daemon" || name == "nobody" || uid < 0
		if system && uid != 0 {
			continue
		}
		snap.Users = append(snap.Users, account{Name: name, UID: uid, Shell: shells[name]})
	}

	g, err := runCmd(ctx, 15*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	if err == nil {
		if _, members, ok := strings.Cut(g, ":"); ok {
			snap.Admins = strings.Fields(members)
		}
	}
	return snap, nil
}
