package mtp

import (
	"errors"
	"strings"
)

// Device is an MTP / PTP capable USB device found on the bus.
type Device struct {
	ID        string // mtp-<bus>-<address>
	Name      string
	Vendor    string
	Serial    string
	VendorID  int
	ProductID int

	bus, addr int
	iface     int
	epIn      uint8
	epOut     uint8
	maxPacket int
	path      string // linux: /dev/bus/usb/BBB/DDD
}

var (
	// ErrBusy: another program (Android File Transfer, OpenMTP, gvfs, a browser
	// using WebUSB ...) holds the device.
	ErrBusy = errors.New("다른 프로그램이 장치를 사용 중 — USB 감시의 '모두 종료'로 점유 프로그램을 종료한 뒤 다시 시도하세요")
	// ErrNoLibusb: macOS needs libusb at runtime.
	ErrNoLibusb    = errors.New("libusb 를 찾을 수 없음 — `brew install libusb` 후 서버를 다시 시작하세요")
	ErrUnsupported = errors.New("이 OS 에서는 MTP 를 지원하지 않음")
	ErrNotFound    = errors.New("MTP 장치가 연결되어 있지 않음 (분리되었거나 USB 모드가 바뀜)")
	ErrPermission  = errors.New("USB 장치 접근 권한 없음 — root 로 실행하거나 udev 규칙(예: android-udev-rules)이 필요")
)

// isMTPInterface: still-image class (PTP / MTP), or the vendor-specific
// interface Android uses for MTP (identified by its "MTP" interface string).
func isMTPInterface(class, sub, proto int, name string) bool {
	if class == 6 && sub == 1 && proto == 1 {
		return true
	}
	return class == 0xff && strings.Contains(strings.ToUpper(name), "MTP")
}

// Open claims the device's MTP interface and starts a session.
func (d Device) Open() (*Session, error) {
	t, err := openTransport(d)
	if err != nil {
		return nil, err
	}
	return OpenSession(t)
}

// Devices lists connected MTP devices.
func Devices() ([]Device, error) { return listDevices() }
