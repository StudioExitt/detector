package detect

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
)

type account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	Shell string `json:"shell"`
}

type accountsSnapshot struct {
	Users      []account // interactive / real users (system accounts filtered per OS)
	Admins     []string  // members of admin / sudo / wheel
	NoPassword []string  // accounts with an empty password (when readable)
	AdminGroup string
}

type accountsBaseline struct {
	Users    []string `json:"users"`
	Admins   []string `json:"admins"`
	Reported []string `json:"reported"` // one-shot findings already reported (uid0:<name>, nopw:<name>)
}

type accountsDetector struct{}

func newAccountsDetector() Detector { return &accountsDetector{} }

func (d *accountsDetector) Name() string { return "accounts" }

// CompactSuccessfulRuns: account lists rarely change, so only the latest
// successful run is kept; runs with findings or errors stay in the history.
func (d *accountsDetector) CompactSuccessfulRuns() bool { return true }

func (d *accountsDetector) Check(ctx context.Context, env *Env) (Report, error) {
	snap, err := listAccounts(ctx)
	if err != nil {
		return Report{}, err
	}

	var base accountsBaseline
	found, err := env.State.Load(ctx, "baseline", &base)
	if err != nil {
		return Report{}, err
	}

	users := make([]string, 0, len(snap.Users))
	for _, u := range snap.Users {
		users = append(users, u.Name)
	}
	sort.Strings(users)
	admins := slices.Clone(snap.Admins)
	sort.Strings(admins)

	var findings []Finding
	reported := map[string]bool{}
	for _, r := range base.Reported {
		reported[r] = true
	}
	once := func(key string, f Finding) {
		if !reported[key] {
			reported[key] = true
			findings = append(findings, f)
		}
	}

	// always-on checks
	for _, u := range snap.Users {
		if u.UID == 0 && u.Name != "root" {
			once("uid0:"+u.Name, Finding{Rule: "account.uid0", Category: CategoryIntrusion, Severity: SevCritical, Source: env.Host, Key: u.Name,
				Message: fmt.Sprintf("root 이외의 UID 0 계정: %s (shell %s) — 숨은 관리자 계정 의심", u.Name, u.Shell)})
		}
	}
	for _, n := range snap.NoPassword {
		once("nopw:"+n, Finding{Rule: "account.no_password", Category: CategoryIntrusion, Severity: SevHigh, Source: env.Host, Key: n,
			Message: fmt.Sprintf("비밀번호가 비어 있는 계정: %s", n)})
	}

	// diff against the baseline
	if found {
		for _, u := range snap.Users {
			if !slices.Contains(base.Users, u.Name) {
				findings = append(findings, Finding{Rule: "account.added", Category: CategoryIntrusion, Severity: SevHigh, Source: env.Host, Key: u.Name,
					Message: fmt.Sprintf("새 사용자 계정 생성: %s (uid %d, shell %s)", u.Name, u.UID, u.Shell)})
			}
		}
		for _, n := range base.Users {
			if !slices.Contains(users, n) {
				findings = append(findings, Finding{Rule: "account.removed", Category: CategoryIntrusion, Severity: SevLow, Source: env.Host, Key: n,
					Message: fmt.Sprintf("사용자 계정 삭제: %s", n)})
			}
		}
		for _, n := range admins {
			if !slices.Contains(base.Admins, n) {
				findings = append(findings, Finding{Rule: "account.admin_added", Category: CategoryIntrusion, Severity: SevHigh, Source: env.Host, Key: n,
					Message: fmt.Sprintf("관리자 그룹(%s)에 추가됨: %s — 권한 상승 의심", snap.AdminGroup, n)})
			}
		}
		for _, n := range base.Admins {
			if !slices.Contains(admins, n) {
				findings = append(findings, Finding{Rule: "account.admin_removed", Category: CategoryIntrusion, Severity: SevLow, Source: env.Host, Key: n,
					Message: fmt.Sprintf("관리자 그룹(%s)에서 제외됨: %s", snap.AdminGroup, n)})
			}
		}
	}

	base = accountsBaseline{Users: users, Admins: admins, Reported: sortedKeys(reported)}
	if err := env.State.Save(ctx, "baseline", base); err != nil {
		return Report{}, err
	}

	checks := []Check{
		{Name: "users", Status: CheckOK, Detail: strings.Join(users, ", ")},
		{Name: "admins (" + snap.AdminGroup + ")", Status: CheckOK, Detail: strings.Join(admins, ", ")},
	}
	for _, u := range snap.Users {
		if u.UID == 0 && u.Name != "root" {
			checks = append(checks, Check{Name: "uid 0: " + u.Name, Status: CheckFail, Detail: "root 이외의 UID 0 계정"})
		}
	}
	for _, n := range snap.NoPassword {
		checks = append(checks, Check{Name: "empty password: " + n, Status: CheckFail, Detail: "비밀번호 없음"})
	}

	summary := fmt.Sprintf("사용자 %d명, 관리자 %d명", len(users), len(admins))
	if !found {
		summary = "기준선 생성: " + summary
	}
	return Report{Findings: findings, Summary: summary, Checks: checks}, nil
}
