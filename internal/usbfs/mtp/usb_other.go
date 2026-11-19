//go:build !darwin && !linux

package mtp

func listDevices() ([]Device, error)          { return nil, ErrUnsupported }
func openTransport(Device) (Transport, error) { return nil, ErrUnsupported }
