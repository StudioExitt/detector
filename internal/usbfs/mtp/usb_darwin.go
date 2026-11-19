//go:build darwin

package mtp

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// libusb loaded at runtime (Homebrew / MacPorts) through purego: no cgo.

var libusbPaths = []string{
	"/opt/homebrew/lib/libusb-1.0.0.dylib",
	"/usr/local/lib/libusb-1.0.0.dylib",
	"/opt/local/lib/libusb-1.0.0.dylib",
	"libusb-1.0.0.dylib",
}

type deviceDescriptor struct {
	BLength            uint8
	BDescriptorType    uint8
	BcdUSB             uint16
	BDeviceClass       uint8
	BDeviceSubClass    uint8
	BDeviceProtocol    uint8
	BMaxPacketSize0    uint8
	IDVendor           uint16
	IDProduct          uint16
	BcdDevice          uint16
	IManufacturer      uint8
	IProduct           uint8
	ISerialNumber      uint8
	BNumConfigurations uint8
}

type configDescriptor struct {
	BLength             uint8
	BDescriptorType     uint8
	WTotalLength        uint16
	BNumInterfaces      uint8
	BConfigurationValue uint8
	IConfiguration      uint8
	BmAttributes        uint8
	MaxPower            uint8
	Interface           *usbInterface
	Extra               *byte
	ExtraLength         int32
}

type usbInterface struct {
	Altsetting    *interfaceDescriptor
	NumAltsetting int32
}

type interfaceDescriptor struct {
	BLength            uint8
	BDescriptorType    uint8
	BInterfaceNumber   uint8
	BAlternateSetting  uint8
	BNumEndpoints      uint8
	BInterfaceClass    uint8
	BInterfaceSubClass uint8
	BInterfaceProtocol uint8
	IInterface         uint8
	Endpoint           *endpointDescriptor
	Extra              *byte
	ExtraLength        int32
}

type endpointDescriptor struct {
	BLength          uint8
	BDescriptorType  uint8
	BEndpointAddress uint8
	BmAttributes     uint8
	WMaxPacketSize   uint16
	BInterval        uint8
	BRefresh         uint8
	BSynchAddress    uint8
	Extra            *byte
	ExtraLength      int32
}

var (
	luOnce sync.Once
	luErr  error
	luCtx  uintptr

	luInit                func(ctx *uintptr) int32
	luGetDeviceList       func(ctx uintptr, list **uintptr) int
	luFreeDeviceList      func(list *uintptr, unref int32)
	luGetDeviceDescriptor func(dev uintptr, desc *deviceDescriptor) int32
	luGetActiveConfig     func(dev uintptr, cfg **configDescriptor) int32
	luGetConfig           func(dev uintptr, idx uint8, cfg **configDescriptor) int32
	luFreeConfig          func(cfg *configDescriptor)
	luGetBusNumber        func(dev uintptr) uint8
	luGetDeviceAddress    func(dev uintptr) uint8
	luOpen                func(dev uintptr, h *uintptr) int32
	luClose               func(h uintptr)
	luGetStringASCII      func(h uintptr, idx uint8, data *byte, length int32) int32
	luClaimInterface      func(h uintptr, iface int32) int32
	luReleaseInterface    func(h uintptr, iface int32) int32
	luBulkTransfer        func(h uintptr, ep uint8, data *byte, length int32, transferred *int32, timeout uint32) int32
	luClearHalt           func(h uintptr, ep uint8) int32
	luErrorName           func(code int32) string
)

const (
	luErrIO       = -1
	luErrAccess   = -3
	luErrNoDevice = -4
	luErrBusy     = -6
	luErrTimeout  = -7
	luErrPipe     = -9
)

func loadLibusb() error {
	luOnce.Do(func() {
		var lib uintptr
		for _, p := range libusbPaths {
			h, err := purego.Dlopen(p, purego.RTLD_NOW|purego.RTLD_LOCAL)
			if err == nil {
				lib = h
				break
			}
		}
		if lib == 0 {
			luErr = ErrNoLibusb
			return
		}
		reg := func(fn any, name string) { purego.RegisterLibFunc(fn, lib, name) }
		reg(&luInit, "libusb_init")
		reg(&luGetDeviceList, "libusb_get_device_list")
		reg(&luFreeDeviceList, "libusb_free_device_list")
		reg(&luGetDeviceDescriptor, "libusb_get_device_descriptor")
		reg(&luGetActiveConfig, "libusb_get_active_config_descriptor")
		reg(&luGetConfig, "libusb_get_config_descriptor")
		reg(&luFreeConfig, "libusb_free_config_descriptor")
		reg(&luGetBusNumber, "libusb_get_bus_number")
		reg(&luGetDeviceAddress, "libusb_get_device_address")
		reg(&luOpen, "libusb_open")
		reg(&luClose, "libusb_close")
		reg(&luGetStringASCII, "libusb_get_string_descriptor_ascii")
		reg(&luClaimInterface, "libusb_claim_interface")
		reg(&luReleaseInterface, "libusb_release_interface")
		reg(&luBulkTransfer, "libusb_bulk_transfer")
		reg(&luClearHalt, "libusb_clear_halt")
		reg(&luErrorName, "libusb_error_name")
		if rc := luInit(&luCtx); rc != 0 {
			luErr = fmt.Errorf("libusb_init 실패: %s", luErrorName(rc))
		}
	})
	return luErr
}

func luError(op string, rc int32) error {
	switch rc {
	case luErrAccess, luErrBusy:
		return ErrBusy
	case luErrNoDevice:
		return ErrNotFound
	}
	return fmt.Errorf("%s: %s", op, luErrorName(rc))
}

// withDevices calls fn for each device on the bus; the list is freed after.
func withDevices(fn func(dev uintptr) bool) error {
	if err := loadLibusb(); err != nil {
		return err
	}
	var list *uintptr
	n := luGetDeviceList(luCtx, &list)
	if n < 0 {
		return fmt.Errorf("libusb_get_device_list: %s", luErrorName(int32(n)))
	}
	defer luFreeDeviceList(list, 1)
	for _, dev := range unsafe.Slice(list, n) {
		if !fn(dev) {
			break
		}
	}
	return nil
}

func luString(h uintptr, idx uint8) string {
	if h == 0 || idx == 0 {
		return ""
	}
	buf := make([]byte, 256)
	n := luGetStringASCII(h, idx, &buf[0], int32(len(buf)))
	if n <= 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

// probe returns the MTP interface of dev (ok=false when it has none).
func probe(dev uintptr) (Device, bool) {
	var desc deviceDescriptor
	if luGetDeviceDescriptor(dev, &desc) != 0 || desc.BDeviceClass == 9 {
		return Device{}, false
	}
	var cfg *configDescriptor
	if luGetActiveConfig(dev, &cfg) != 0 {
		if luGetConfig(dev, 0, &cfg) != 0 {
			return Device{}, false
		}
	}
	defer luFreeConfig(cfg)

	type cand struct {
		ifd *interfaceDescriptor
	}
	var cands []cand
	for _, it := range unsafe.Slice(cfg.Interface, cfg.BNumInterfaces) {
		if it.NumAltsetting < 1 {
			continue
		}
		ifd := &unsafe.Slice(it.Altsetting, it.NumAltsetting)[0]
		if c := ifd.BInterfaceClass; c == 6 || c == 0xff {
			cands = append(cands, cand{ifd})
		}
	}
	if len(cands) == 0 {
		return Device{}, false
	}

	var h uintptr
	if luOpen(dev, &h) != 0 {
		h = 0 // still usable without strings for class 6
	}
	if h != 0 {
		defer luClose(h)
	}
	for _, c := range cands {
		ifd := c.ifd
		if !isMTPInterface(int(ifd.BInterfaceClass), int(ifd.BInterfaceSubClass), int(ifd.BInterfaceProtocol), luString(h, ifd.IInterface)) {
			continue
		}
		d := Device{
			ID:        fmt.Sprintf("mtp-%d-%d", luGetBusNumber(dev), luGetDeviceAddress(dev)),
			VendorID:  int(desc.IDVendor),
			ProductID: int(desc.IDProduct),
			Vendor:    luString(h, desc.IManufacturer),
			Name:      luString(h, desc.IProduct),
			Serial:    luString(h, desc.ISerialNumber),
			bus:       int(luGetBusNumber(dev)),
			addr:      int(luGetDeviceAddress(dev)),
			iface:     int(ifd.BInterfaceNumber),
		}
		if ifd.BNumEndpoints > 0 {
			for _, ep := range unsafe.Slice(ifd.Endpoint, ifd.BNumEndpoints) {
				if ep.BmAttributes&3 != 2 { // bulk only
					continue
				}
				if ep.BEndpointAddress&0x80 != 0 {
					d.epIn = ep.BEndpointAddress
				} else {
					d.epOut = ep.BEndpointAddress
				}
				d.maxPacket = int(ep.WMaxPacketSize & 0x7ff)
			}
		}
		if d.epIn == 0 || d.epOut == 0 {
			continue
		}
		if d.Name == "" {
			d.Name = fmt.Sprintf("USB %04x:%04x", d.VendorID, d.ProductID)
		}
		return d, true
	}
	return Device{}, false
}

func listDevices() ([]Device, error) {
	var out []Device
	err := withDevices(func(dev uintptr) bool {
		if d, ok := probe(dev); ok {
			out = append(out, d)
		}
		return true
	})
	return out, err
}

type luTransport struct {
	h      uintptr
	d      Device
	closed bool
}

func openTransport(d Device) (Transport, error) {
	var h uintptr
	var rc int32 = 1
	found := false
	err := withDevices(func(dev uintptr) bool {
		if int(luGetBusNumber(dev)) != d.bus || int(luGetDeviceAddress(dev)) != d.addr {
			return true
		}
		found = true
		rc = luOpen(dev, &h)
		return false
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	if rc != 0 {
		return nil, luError("libusb_open", rc)
	}
	if rc := luClaimInterface(h, int32(d.iface)); rc != 0 {
		luClose(h)
		return nil, luError("libusb_claim_interface", rc)
	}
	return &luTransport{h: h, d: d}, nil
}

func (t *luTransport) xfer(ep uint8, p []byte, timeout time.Duration) (int, error) {
	var ptr *byte
	if len(p) > 0 {
		ptr = &p[0]
	}
	var n int32
	rc := luBulkTransfer(t.h, ep, ptr, int32(len(p)), &n, uint32(timeout.Milliseconds()))
	switch rc {
	case 0:
		return int(n), nil
	case luErrPipe:
		luClearHalt(t.h, ep)
		return int(n), fmt.Errorf("USB 엔드포인트 정지(stall)")
	case luErrTimeout:
		return int(n), fmt.Errorf("USB 응답 시간 초과 — 휴대폰 화면 잠금을 풀었는지 확인하세요")
	case luErrNoDevice:
		return int(n), ErrNotFound
	case luErrIO:
		return int(n), fmt.Errorf("USB 입출력 오류")
	}
	return int(n), fmt.Errorf("libusb_bulk_transfer: %s", luErrorName(rc))
}

func (t *luTransport) BulkOut(p []byte, timeout time.Duration) (int, error) {
	return t.xfer(t.d.epOut, p, timeout)
}
func (t *luTransport) BulkIn(p []byte, timeout time.Duration) (int, error) {
	return t.xfer(t.d.epIn, p, timeout)
}
func (t *luTransport) MaxPacket() int {
	if t.d.maxPacket <= 0 {
		return 512
	}
	return t.d.maxPacket
}
func (t *luTransport) BufSize() int { return 256 * 1024 }

func (t *luTransport) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	luReleaseInterface(t.h, int32(t.d.iface))
	luClose(t.h)
	return nil
}
