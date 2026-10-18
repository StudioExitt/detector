package detect

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// CoreAudio / CoreMediaIO bindings through purego (no cgo). They answer
// "is any process using this microphone / camera right now" from the HAL,
// which is what drives the orange/green menu bar indicators.

type avAddr struct{ selector, scope, element uint32 }

func fourCC(s string) uint32 {
	return uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
}

var (
	selDevices       = fourCC("dev#")
	selRunningAny    = fourCC("gone") // kAudio/CMIODevicePropertyDeviceIsRunningSomewhere
	selName          = fourCC("lnam")
	selStreams       = fourCC("stm#")
	selProcessList   = fourCC("prs#") // kAudioHardwarePropertyProcessObjectList (macOS 14+)
	selProcRunningIn = fourCC("piri") // kAudioProcessPropertyIsRunningInput
	selProcPID       = fourCC("ppid")
	selProcBundleID  = fourCC("pbid")
	scopeGlobal      = fourCC("glob")
	scopeInput       = fourCC("inpt")
)

const (
	avSystemObject   = 1
	cfStringEncUTF8  = 0x08000100
	avMaxObjectCount = 256
)

var (
	avOnce sync.Once
	avErr  error

	audioGetSize func(obj uint32, addr *avAddr, qSize uint32, q unsafe.Pointer, size *uint32) int32
	audioGetData func(obj uint32, addr *avAddr, qSize uint32, q unsafe.Pointer, size *uint32, out unsafe.Pointer) int32
	cmioGetSize  func(obj uint32, addr *avAddr, qSize uint32, q unsafe.Pointer, size *uint32) int32
	cmioGetData  func(obj uint32, addr *avAddr, qSize uint32, q unsafe.Pointer, size uint32, used *uint32, out unsafe.Pointer) int32
	cfGetCString func(s uintptr, buf *byte, size int64, enc uint32) bool
	cfRelease    func(uintptr)
)

func loadAV() error {
	avOnce.Do(func() {
		libs := map[string]uintptr{}
		for _, p := range []string{
			"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
			"/System/Library/Frameworks/CoreAudio.framework/CoreAudio",
			"/System/Library/Frameworks/CoreMediaIO.framework/CoreMediaIO",
		} {
			h, err := purego.Dlopen(p, purego.RTLD_GLOBAL|purego.RTLD_NOW)
			if err != nil {
				avErr = fmt.Errorf("load %s: %w", p, err)
				return
			}
			libs[p] = h
		}
		cf := libs["/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"]
		ca := libs["/System/Library/Frameworks/CoreAudio.framework/CoreAudio"]
		io := libs["/System/Library/Frameworks/CoreMediaIO.framework/CoreMediaIO"]
		purego.RegisterLibFunc(&cfGetCString, cf, "CFStringGetCString")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")
		purego.RegisterLibFunc(&audioGetSize, ca, "AudioObjectGetPropertyDataSize")
		purego.RegisterLibFunc(&audioGetData, ca, "AudioObjectGetPropertyData")
		purego.RegisterLibFunc(&cmioGetSize, io, "CMIOObjectGetPropertyDataSize")
		purego.RegisterLibFunc(&cmioGetData, io, "CMIOObjectGetPropertyData")
	})
	return avErr
}

// AVProcess is a process currently capturing audio input (macOS 14+).
type AVProcess struct {
	PID      int
	BundleID string
}

func cfString(ref uintptr) string {
	if ref == 0 {
		return ""
	}
	defer cfRelease(ref)
	buf := make([]byte, 512)
	if !cfGetCString(ref, &buf[0], int64(len(buf)), cfStringEncUTF8) {
		return ""
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// audioObjects returns the object IDs listed by a system property.
func audioObjects(sel uint32) ([]uint32, error) {
	a := avAddr{sel, scopeGlobal, 0}
	var size uint32
	if st := audioGetSize(avSystemObject, &a, 0, nil, &size); st != 0 {
		return nil, fmt.Errorf("AudioObjectGetPropertyDataSize(%08x): %d", sel, st)
	}
	n := min(int(size/4), avMaxObjectCount)
	if n == 0 {
		return nil, nil
	}
	ids := make([]uint32, n)
	size = uint32(n * 4)
	if st := audioGetData(avSystemObject, &a, 0, nil, &size, unsafe.Pointer(&ids[0])); st != 0 {
		return nil, fmt.Errorf("AudioObjectGetPropertyData(%08x): %d", sel, st)
	}
	return ids[:size/4], nil
}

func audioU32(obj, sel, scope uint32) (uint32, bool) {
	a := avAddr{sel, scope, 0}
	var v uint32
	size := uint32(4)
	return v, audioGetData(obj, &a, 0, nil, &size, unsafe.Pointer(&v)) == 0
}

func audioString(obj, sel uint32) string {
	a := avAddr{sel, scopeGlobal, 0}
	var ref uintptr
	size := uint32(unsafe.Sizeof(ref))
	if audioGetData(obj, &a, 0, nil, &size, unsafe.Pointer(&ref)) != 0 {
		return ""
	}
	return cfString(ref)
}

// listMicrophones returns audio input devices and whether any process is
// recording from each.
func listMicrophones() ([]AVDevice, error) {
	if err := loadAV(); err != nil {
		return nil, err
	}
	ids, err := audioObjects(selDevices)
	if err != nil {
		return nil, err
	}
	var out []AVDevice
	for _, id := range ids {
		a := avAddr{selStreams, scopeInput, 0}
		var size uint32
		if audioGetSize(id, &a, 0, nil, &size) != 0 || size == 0 {
			continue // output-only device
		}
		running, _ := audioU32(id, selRunningAny, scopeGlobal)
		out = append(out, AVDevice{Name: orNone(audioString(id, selName)), Kind: "mic", InUse: running != 0})
	}
	return out, nil
}

// audioInputProcesses lists processes recording audio. Requires macOS 14
// (process objects); returns an error on older systems.
func audioInputProcesses() ([]AVProcess, error) {
	if err := loadAV(); err != nil {
		return nil, err
	}
	ids, err := audioObjects(selProcessList)
	if err != nil {
		return nil, err
	}
	var out []AVProcess
	for _, id := range ids {
		if v, ok := audioU32(id, selProcRunningIn, scopeGlobal); !ok || v == 0 {
			continue
		}
		pid, _ := audioU32(id, selProcPID, scopeGlobal)
		out = append(out, AVProcess{PID: int(int32(pid)), BundleID: audioString(id, selProcBundleID)})
	}
	return out, nil
}

// listCameras returns video capture devices (built-in, USB, virtual cameras)
// and whether any process is streaming from each.
func listCameras() ([]AVDevice, error) {
	if err := loadAV(); err != nil {
		return nil, err
	}
	a := avAddr{selDevices, scopeGlobal, 0}
	var size uint32
	if st := cmioGetSize(avSystemObject, &a, 0, nil, &size); st != 0 {
		return nil, fmt.Errorf("CMIOObjectGetPropertyDataSize: %d", st)
	}
	n := min(int(size/4), avMaxObjectCount)
	if n == 0 {
		return nil, nil
	}
	ids := make([]uint32, n)
	var used uint32
	if st := cmioGetData(avSystemObject, &a, 0, nil, uint32(n*4), &used, unsafe.Pointer(&ids[0])); st != 0 {
		return nil, fmt.Errorf("CMIOObjectGetPropertyData: %d", st)
	}
	var out []AVDevice
	for _, id := range ids[:used/4] {
		var running uint32
		ra := avAddr{selRunningAny, scopeGlobal, 0}
		cmioGetData(id, &ra, 0, nil, 4, &used, unsafe.Pointer(&running))
		var ref uintptr
		na := avAddr{selName, scopeGlobal, 0}
		name := ""
		if cmioGetData(id, &na, 0, nil, uint32(unsafe.Sizeof(ref)), &used, unsafe.Pointer(&ref)) == 0 {
			name = cfString(ref)
		}
		out = append(out, AVDevice{Name: orNone(name), Kind: "camera", InUse: running != 0})
	}
	return out, nil
}
