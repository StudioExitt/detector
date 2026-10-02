package detect

import (
	"context"
	"fmt"
)

// postureCheck evaluates one security setting. status is CheckOK / CheckWarn / CheckFail.
type postureCheck struct {
	ID       string
	Title    string
	Severity string // severity when the setting is weak
	Run      func(ctx context.Context) (status, detail string, err error)
}

type postureDetector struct {
	checks []postureCheck
}

func newPostureDetector() Detector {
	cs := postureChecks()
	if len(cs) == 0 {
		return nil
	}
	return &postureDetector{checks: cs}
}

func (d *postureDetector) Name() string { return "posture" }

// Weak settings are reported once when first seen (vulnerability_scan). A
// setting that was OK and became weak is reported as a possible intrusion,
// since attackers commonly disable SIP/Gatekeeper/firewall.
func (d *postureDetector) Check(ctx context.Context, env *Env) (Report, error) {
	prev := map[string]string{}
	if _, err := env.State.Load(ctx, "status", &prev); err != nil {
		return Report{}, err
	}
	next := map[string]string{}
	var findings []Finding
	var checks []Check
	weak := 0
	for _, c := range d.checks {
		status, detail, err := c.Run(ctx)
		if err != nil {
			checks = append(checks, Check{Name: c.Title, Status: CheckWarn, Detail: "확인 불가: " + err.Error()})
			if p, ok := prev[c.ID]; ok {
				next[c.ID] = p // keep the last known state
			}
			continue
		}
		checks = append(checks, Check{Name: c.Title, Status: status, Detail: detail})
		next[c.ID] = status
		if status == CheckOK {
			continue
		}
		weak++
		switch prev[c.ID] {
		case CheckOK:
			findings = append(findings, Finding{
				Rule: "posture." + c.ID, Category: CategoryIntrusion, Severity: c.Severity, Source: env.Host, Key: c.ID + "|changed",
				Message: fmt.Sprintf("보안 설정이 약화됨: %s — %s (이전: 정상)", c.Title, detail),
			})
		case "":
			findings = append(findings, Finding{
				Rule: "posture." + c.ID, Category: CategoryVulnScan, Severity: c.Severity, Source: env.Host, Key: c.ID,
				Message: fmt.Sprintf("취약한 보안 설정: %s — %s", c.Title, detail),
			})
		}
	}
	if err := env.State.Save(ctx, "status", next); err != nil {
		return Report{}, err
	}
	return Report{
		Findings: findings,
		Summary:  fmt.Sprintf("보안 설정 %d개 점검 — 취약 %d개", len(d.checks), weak),
		Checks:   checks,
	}, nil
}
