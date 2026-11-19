//go:build !darwin && !linux

package usbfs

func diskSpace(string) (int64, int64) { return 0, 0 }
