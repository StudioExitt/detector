//go:build darwin || linux

package detect

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

// killAndWait sends SIGTERM and waits up to 3s; with hard, survivors get
// SIGKILL (and another 2s). Returns whether the process is gone.
func killAndWait(pid int, hard bool) (bool, string) {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return killErr(err)
	}
	if waitExit(pid, 3*time.Second) {
		return true, "종료됨 (SIGTERM)"
	}
	if !hard {
		return false, "3초 안에 종료되지 않음 — 강제 종료(SIGKILL)를 사용하세요"
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return killErr(err)
	}
	if waitExit(pid, 2*time.Second) {
		return true, "강제 종료됨 (SIGKILL)"
	}
	return false, "SIGKILL 후에도 종료되지 않음 (장치 입출력 대기 중일 수 있음)"
}

func killErr(err error) (bool, string) {
	switch {
	case errors.Is(err, syscall.ESRCH):
		return true, "이미 종료됨"
	case errors.Is(err, syscall.EPERM):
		return false, "권한 없음 — 다른 사용자/시스템 프로세스는 root 로 실행해야 종료 가능"
	}
	return false, fmt.Sprintf("종료 실패: %v", err)
}

func waitExit(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
