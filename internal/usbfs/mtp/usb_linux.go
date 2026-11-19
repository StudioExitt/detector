//go:build linux

package mtp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Linux: devices from sysfs, transfers through usbfs ioctls (pure Go).

const sysUsb = "/sys/bus/usb/devices"

func sysRead(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func sysHex(p string) int {
	v, _ := strconv.ParseInt(sysRead(p), 16, 64)
	return int(v)
}

func sysDec(p string) int {
	v, _ := strconv.Atoi(sysRead(p))
	return v
}

func listDevices() ([]Device, error) {
	ents, err := os.ReadDir(sysUsb)
	if err != nil {
		return nil, err
	}
	var out []Device
	for _, e := range ents {
		name := e.Name()
		if strings.Contains(name, ":") || strings.HasPrefix(name, "usb") {
			continue
		}
		dir := filepath.Join(sysUsb, name)
		if sysHex(filepath.Join(dir, "bDeviceClass")) == 9 {
			continue
		}
		ifs, _ := filepath.Glob(filepath.Join(sysUsb, name+":*"))
		for _, ifd := range ifs {
			class := sysHex(filepath.Join(ifd, "bInterfaceClass"))
			sub := sysHex(filepath.Join(ifd, "bInterfaceSubClass"))
			proto := sysHex(filepath.Join(ifd, "bInterfaceProtocol"))
			if !isMTPInterface(class, sub, proto, sysRead(filepath.Join(ifd, "interface"))) {
				continue
			}
			d := Device{
				VendorID:  sysHex(filepath.Join(dir, "idVendor")),
				ProductID: sysHex(filepath.Join(dir, "idProduct")),
				Vendor:    sysRead(filepath.Join(dir, "manufacturer")),
				Name:      sysRead(filepath.Join(dir, "product")),
				Serial:    sysRead(filepath.Join(dir, "serial")),
				bus:       sysDec(filepath.Join(dir, "busnum")),
				addr:      sysDec(filepath.Join(dir, "devnum")),
				iface:     sysHex(filepath.Join(ifd, "bInterfaceNumber")),
			}
			eps, _ := filepath.Glob(filepath.Join(ifd, "ep_*"))
			for _, ep := range eps {
				if sysRead(filepath.Join(ep, "type")) != "Bulk" {
					continue
				}
				a := uint8(sysHex(filepath.Join(ep, "bEndpointAddress")))
				if a&0x80 != 0 {
					d.epIn = a
				} else {
					d.epOut = a
				}
				d.maxPacket = sysHex(filepath.Join(ep, "wMaxPacketSize")) & 0x7ff
			}
			if d.epIn == 0 || d.epOut == 0 {
				continue
			}
			d.ID = fmt.Sprintf("mtp-%d-%d", d.bus, d.addr)
			d.path = fmt.Sprintf("/dev/bus/usb/%03d/%03d", d.bus, d.addr)
			if d.Name == "" {
				d.Name = fmt.Sprintf("USB %04x:%04x", d.VendorID, d.ProductID)
			}
			out = append(out, d)
			break
		}
	}
	return out, nil
}

// struct usbdevfs_bulktransfer
type bulkTransfer struct {
	Ep      uint32
	Len     uint32
	Timeout uint32 // ms
	Data    uintptr
}

func ioc(dir, nr, size uintptr) uintptr { return dir<<30 | size<<16 | 'U'<<8 | nr }

var (
	iocBulk       = ioc(3, 2, unsafe.Sizeof(bulkTransfer{}))
	iocClaim      = ioc(2, 15, 4)
	iocRelease    = ioc(2, 16, 4)
	iocClearHalt  = ioc(2, 21, 4)
	errStall      = errors.New("USB 엔드포인트 정지(stall)")
	errUSBTimeout = errors.New("USB 응답 시간 초과 — 휴대폰 화면 잠금을 풀었는지 확인하세요")
)

func ioctl(fd int, req uintptr, arg unsafe.Pointer) (int, error) {
	r, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if e != 0 {
		return int(r), e
	}
	return int(r), nil
}

type fsTransport struct {
	f *os.File
	d Device
}

func openTransport(d Device) (Transport, error) {
	f, err := os.OpenFile(d.path, os.O_RDWR, 0)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, ErrNotFound
		case errors.Is(err, os.ErrPermission):
			return nil, ErrPermission
		}
		return nil, err
	}
	n := uint32(d.iface)
	if _, err := ioctl(int(f.Fd()), iocClaim, unsafe.Pointer(&n)); err != nil {
		f.Close()
		if errors.Is(err, syscall.EBUSY) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("USB 인터페이스 점유 실패: %w", err)
	}
	return &fsTransport{f: f, d: d}, nil
}

func (t *fsTransport) xfer(ep uint8, p []byte, timeout time.Duration) (int, error) {
	bt := bulkTransfer{Ep: uint32(ep), Len: uint32(len(p)), Timeout: uint32(timeout.Milliseconds())}
	if len(p) > 0 {
		bt.Data = uintptr(unsafe.Pointer(&p[0]))
	}
	n, err := ioctl(int(t.f.Fd()), iocBulk, unsafe.Pointer(&bt))
	runtime.KeepAlive(p)
	if err == nil {
		return n, nil
	}
	switch {
	case errors.Is(err, syscall.EPIPE):
		e := uint32(ep)
		_, _ = ioctl(int(t.f.Fd()), iocClearHalt, unsafe.Pointer(&e))
		return 0, errStall
	case errors.Is(err, syscall.ETIMEDOUT):
		return 0, errUSBTimeout
	case errors.Is(err, syscall.ENODEV):
		return 0, ErrNotFound
	}
	return 0, fmt.Errorf("USB 전송 실패: %w", err)
}

func (t *fsTransport) BulkOut(p []byte, timeout time.Duration) (int, error) {
	return t.xfer(t.d.epOut, p, timeout)
}
func (t *fsTransport) BulkIn(p []byte, timeout time.Duration) (int, error) {
	return t.xfer(t.d.epIn, p, timeout)
}
func (t *fsTransport) MaxPacket() int {
	if t.d.maxPacket <= 0 {
		return 512
	}
	return t.d.maxPacket
}
func (t *fsTransport) BufSize() int { return 128 * 1024 }

func (t *fsTransport) Close() error {
	n := uint32(t.d.iface)
	_, _ = ioctl(int(t.f.Fd()), iocRelease, unsafe.Pointer(&n))
	return t.f.Close()
}
