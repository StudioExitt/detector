package detect

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
)

var adminGroups = []string{"sudo", "wheel", "admin"}

// listAccounts parses /etc/passwd, /etc/group and (when readable) /etc/shadow.
// System accounts (uid < 1000 without a login shell) are skipped.
func listAccounts(context.Context) (accountsSnapshot, error) {
	snap := accountsSnapshot{AdminGroup: strings.Join(adminGroups, "/")}
	primary := map[string][]string{} // gid -> users with that primary group

	err := eachColonLine("/etc/passwd", func(f []string) {
		if len(f) < 7 {
			return
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			return
		}
		primary[f[3]] = append(primary[f[3]], f[0])
		shell := f[6]
		noLogin := strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "/false") || shell == ""
		if uid != 0 && (uid < 1000 || uid == 65534) && noLogin {
			return
		}
		snap.Users = append(snap.Users, account{Name: f[0], UID: uid, Shell: shell})
	})
	if err != nil {
		return snap, err
	}

	seen := map[string]bool{}
	_ = eachColonLine("/etc/group", func(f []string) {
		if len(f) < 4 || !contains(adminGroups, f[0]) {
			return
		}
		members := strings.Split(f[3], ",")
		members = append(members, primary[f[2]]...)
		for _, m := range members {
			if m = strings.TrimSpace(m); m != "" && !seen[m] {
				seen[m] = true
				snap.Admins = append(snap.Admins, m)
			}
		}
	})

	// requires root; silently skipped otherwise
	_ = eachColonLine("/etc/shadow", func(f []string) {
		if len(f) >= 2 && f[1] == "" {
			snap.NoPassword = append(snap.NoPassword, f[0])
		}
	})
	return snap, nil
}

func eachColonLine(path string, fn func([]string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Split(line, ":"))
	}
	return sc.Err()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
