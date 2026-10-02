//go:build !darwin && !linux

package detect

import (
	"context"

	"detector/internal/config"
)

var suspiciousDirs []string

func newAuthSource(config.AuthDetectConfig) authSource  { return nil }
func fimRules() []fimRule                               { return nil }
func fimEnrich(context.Context, string) (string, bool)  { return "", false }
func listListeners(context.Context) ([]listener, error) { return nil, errUnsupported }
func listProcesses(context.Context) ([]proc, error)     { return nil, errUnsupported }
func listAccounts(context.Context) (accountsSnapshot, error) {
	return accountsSnapshot{}, errUnsupported
}
func detectorSources(string) []string { return nil }
func postureChecks() []postureCheck   { return nil }

type sysSampler struct{}

func isSystemExe(string) bool { return false }

func sampleSystem(context.Context, *sysSampler) (SystemSnapshot, []ProcStat, error) {
	return SystemSnapshot{}, nil, errUnsupported
}

type netSampler struct{}

func exeUnsigned(string) (bool, bool) { return false, false }

func sampleNetwork(context.Context, *netSampler) (netRaw, error) { return netRaw{}, errUnsupported }
