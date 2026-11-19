// Package mtp is a small MTP (Media Transfer Protocol, PTP over USB) client:
// enough to list storages and folders, download, upload and delete files on
// Android phones and cameras. USB access is pure Go on Linux (usbfs ioctls)
// and goes through libusb loaded at runtime with purego on macOS, so the
// binary stays cgo-free.
package mtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// container types
const (
	typeCommand  = 1
	typeData     = 2
	typeResponse = 3
)

// operation codes
const (
	opGetDeviceInfo    = 0x1001
	opOpenSession      = 0x1002
	opCloseSession     = 0x1003
	opGetStorageIDs    = 0x1004
	opGetStorageInfo   = 0x1005
	opGetObjectHandles = 0x1007
	opGetObjectInfo    = 0x1008
	opGetObject        = 0x1009
	opDeleteObject     = 0x100B
	opSendObjectInfo   = 0x100C
	opSendObject       = 0x100D
)

// response codes
const (
	rcOK                 = 0x2001
	rcSessionAlreadyOpen = 0x201E
)

// object formats
const (
	FormatUndefined   = 0x3000
	FormatAssociation = 0x3001 // folder
	FormatText        = 0x3004
	FormatWAV         = 0x3008
	FormatMP3         = 0x3009
	FormatJPEG        = 0x3801
)

// RootParent is the parent handle of objects at the top of a storage.
const RootParent = 0xFFFFFFFF

const hdrLen = 12

// ErrBroken means the USB transfer stream is out of sync (an aborted data
// phase, a timeout ...); the device must be closed and opened again.
var ErrBroken = errors.New("MTP 연결이 끊겼거나 응답이 어긋남 — 다시 연결 필요")

// Error is a non-OK MTP response.
type Error struct {
	Op   uint16
	Code uint16
}

var rcText = map[uint16]string{
	0x2002: "일반 오류 (GeneralError)",
	0x2003: "세션이 열리지 않음",
	0x2005: "지원하지 않는 기능",
	0x2008: "잘못된 저장소",
	0x2009: "잘못된 파일 핸들 (이미 삭제되었을 수 있음)",
	0x200C: "저장 공간 부족",
	0x200D: "쓰기 보호된 파일",
	0x200E: "읽기 전용 저장소",
	0x200F: "접근 거부",
	0x2019: "장치가 바쁨",
	0x201D: "잘못된 매개변수",
	0x201E: "세션이 이미 열려 있음",
	0x201F: "취소됨",
	0x2020: "지정한 대상 위치를 쓸 수 없음",
}

func (e *Error) Error() string {
	if t, ok := rcText[e.Code]; ok {
		return fmt.Sprintf("MTP 0x%04x: %s", e.Code, t)
	}
	return fmt.Sprintf("MTP op 0x%04x 실패: 응답 0x%04x", e.Op, e.Code)
}

// Transport is a claimed MTP interface: bulk-in / bulk-out endpoints.
type Transport interface {
	BulkOut(p []byte, timeout time.Duration) (int, error)
	BulkIn(p []byte, timeout time.Duration) (int, error)
	MaxPacket() int // bulk wMaxPacketSize (for zero-length packets)
	BufSize() int   // preferred transfer size, a multiple of MaxPacket
	Close() error
}

// Session is an open MTP session on one device. Not safe for concurrent use.
type Session struct {
	t      Transport
	tid    uint32
	buf    []byte
	broken bool
	mu     sync.Mutex
}

const (
	cmdTimeout  = 10 * time.Second
	dataTimeout = 60 * time.Second
)

// OpenSession starts an MTP session on t. t is closed by Session.Close.
func OpenSession(t Transport) (*Session, error) {
	s := &Session{t: t, buf: make([]byte, t.BufSize())}
	_, err := s.do(opOpenSession, []uint32{1}, nil, 0, nil)
	var me *Error
	if errors.As(err, &me) && me.Code == rcSessionAlreadyOpen {
		// left open by a crashed client: start over
		_, _ = s.do(opCloseSession, nil, nil, 0, nil)
		_, err = s.do(opOpenSession, []uint32{1}, nil, 0, nil)
		if errors.As(err, &me) && me.Code == rcSessionAlreadyOpen {
			err = nil
		}
	}
	if err != nil {
		t.Close()
		return nil, err
	}
	return s, nil
}

// Close ends the session and releases the USB interface.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.broken {
		s.tid++
		_ = s.sendCommand(opCloseSession, nil)
		_, _ = s.readResponse(opCloseSession)
	}
	return s.t.Close()
}

// Broken reports whether the session must be reopened.
func (s *Session) Broken() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.broken
}

func (s *Session) do(op uint16, params []uint32, out io.Reader, outSize int64, in io.Writer) ([]uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken {
		return nil, ErrBroken
	}
	params, err := s.transact(op, params, out, outSize, in)
	var me *Error
	if err != nil && !errors.As(err, &me) && !IsWriterError(err) {
		s.broken = true
		if !errors.Is(err, ErrBroken) {
			err = fmt.Errorf("%w: %v", ErrBroken, err)
		}
	}
	return params, err
}

func (s *Session) transact(op uint16, params []uint32, out io.Reader, outSize int64, in io.Writer) ([]uint32, error) {
	s.tid++
	if err := s.sendCommand(op, params); err != nil {
		return nil, err
	}
	if out != nil {
		if err := s.sendData(op, out, outSize); err != nil {
			return nil, err
		}
	}
	if in != nil {
		done, rp, err := s.readData(op, in)
		if err != nil || done {
			return rp, err
		}
	}
	return s.readResponse(op)
}

func putHeader(b []byte, length uint32, typ, code uint16, tid uint32) {
	binary.LittleEndian.PutUint32(b[0:], length)
	binary.LittleEndian.PutUint16(b[4:], typ)
	binary.LittleEndian.PutUint16(b[6:], code)
	binary.LittleEndian.PutUint32(b[8:], tid)
}

func (s *Session) sendCommand(op uint16, params []uint32) error {
	b := make([]byte, hdrLen+4*len(params))
	putHeader(b, uint32(len(b)), typeCommand, op, s.tid)
	for i, p := range params {
		binary.LittleEndian.PutUint32(b[hdrLen+4*i:], p)
	}
	return s.writeAll(b, cmdTimeout)
}

func (s *Session) writeAll(b []byte, timeout time.Duration) error {
	n, err := s.t.BulkOut(b, timeout)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("short USB write %d/%d", n, len(b))
	}
	return nil
}

// sendData streams the data phase: header + size bytes from r, in chunks
// that are multiples of the packet size, then a zero-length packet when the
// total ends exactly on a packet boundary.
func (s *Session) sendData(op uint16, r io.Reader, size int64) error {
	total := int64(hdrLen) + size
	length := uint32(0xFFFFFFFF)
	if total < 0xFFFFFFFF {
		length = uint32(total)
	}
	buf := s.buf
	putHeader(buf, length, typeData, op, s.tid)
	fill, sent := hdrLen, int64(0)
	for {
		want := len(buf) - fill
		if rem := total - sent - int64(fill); rem < int64(want) {
			want = int(rem)
		}
		n, err := io.ReadFull(r, buf[fill:fill+want])
		if err != nil {
			return fmt.Errorf("원본 읽기 실패: %w", err)
		}
		chunk := fill + n
		if chunk == 0 {
			break
		}
		if err := s.writeAll(buf[:chunk], dataTimeout); err != nil {
			return err
		}
		sent += int64(chunk)
		fill = 0
		if sent >= total {
			break
		}
	}
	if sent%int64(s.t.MaxPacket()) == 0 {
		if _, err := s.t.BulkOut(nil, cmdTimeout); err != nil {
			return err
		}
	}
	return nil
}

// readData reads the data phase into w. done=true when the device answered
// with a response right away (an error before any data).
func (s *Session) readData(op uint16, w io.Writer) (done bool, params []uint32, err error) {
	buf := s.buf
	mp := s.t.MaxPacket()
	n, err := s.readNonEmpty(buf, dataTimeout)
	if err != nil {
		return false, nil, err
	}
	if n < hdrLen {
		return false, nil, fmt.Errorf("짧은 MTP 패킷 (%d bytes)", n)
	}
	length := binary.LittleEndian.Uint32(buf[0:])
	typ := binary.LittleEndian.Uint16(buf[4:])
	if typ == typeResponse {
		p, err := parseResponse(op, s.tid, buf[:n])
		return true, p, err
	}
	if typ != typeData {
		return false, nil, fmt.Errorf("데이터 대신 컨테이너 type %d 수신", typ)
	}
	unknown := length == 0xFFFFFFFF
	remaining := int64(length) - hdrLen
	var werr error
	write := func(p []byte) {
		if werr == nil && len(p) > 0 {
			_, werr = w.Write(p)
		}
	}
	payload := buf[hdrLen:n]
	if !unknown && int64(len(payload)) > remaining {
		payload = payload[:remaining]
	}
	write(payload)
	remaining -= int64(len(payload))
	last := n
	for {
		if unknown {
			if last%mp != 0 || last == 0 {
				break
			}
		} else if remaining <= 0 {
			break
		}
		n, err := s.t.BulkIn(buf, dataTimeout)
		if err != nil {
			return false, nil, err
		}
		p := buf[:n]
		if !unknown && int64(n) > remaining {
			p = p[:remaining]
		}
		write(p)
		remaining -= int64(len(p))
		last = n
	}
	if werr != nil {
		// the device has finished sending; read its response so the stream
		// stays in sync, then report the writer's error
		if _, err := s.readResponse(op); err != nil {
			return true, nil, err
		}
		return true, nil, &writerError{werr}
	}
	return false, nil, nil
}

// writerError is a failure of the local destination during a download; the
// MTP stream itself is still usable.
type writerError struct{ err error }

func (e *writerError) Error() string { return e.err.Error() }
func (e *writerError) Unwrap() error { return e.err }

// readNonEmpty skips zero-length packets (ZLPs ending a previous data phase).
func (s *Session) readNonEmpty(buf []byte, timeout time.Duration) (int, error) {
	for range 3 {
		n, err := s.t.BulkIn(buf, timeout)
		if err != nil || n > 0 {
			return n, err
		}
	}
	return 0, errors.New("빈 USB 패킷만 수신")
}

func (s *Session) readResponse(op uint16) ([]uint32, error) {
	n, err := s.readNonEmpty(s.buf, cmdTimeout)
	if err != nil {
		return nil, err
	}
	return parseResponse(op, s.tid, s.buf[:n])
}

func parseResponse(op uint16, tid uint32, b []byte) ([]uint32, error) {
	if len(b) < hdrLen {
		return nil, fmt.Errorf("짧은 MTP 응답 (%d bytes)", len(b))
	}
	if typ := binary.LittleEndian.Uint16(b[4:]); typ != typeResponse {
		return nil, fmt.Errorf("응답 대신 컨테이너 type %d 수신", typ)
	}
	if got := binary.LittleEndian.Uint32(b[8:]); got != tid {
		return nil, fmt.Errorf("트랜잭션 ID 불일치 (%d != %d)", got, tid)
	}
	var params []uint32
	for i := hdrLen; i+4 <= len(b) && len(params) < 5; i += 4 {
		params = append(params, binary.LittleEndian.Uint32(b[i:]))
	}
	if code := binary.LittleEndian.Uint16(b[6:]); code != rcOK {
		return params, &Error{Op: op, Code: code}
	}
	return params, nil
}

// ── datasets ──

type reader struct {
	b   []byte
	err bool
}

func (r *reader) take(n int) []byte {
	if r.err || len(r.b) < n {
		r.err = true
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u16() uint16 { return binary.LittleEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.LittleEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.LittleEndian.Uint64(r.take(8)) }
func (r *reader) str() string {
	n := int(r.take(1)[0])
	if n == 0 {
		return ""
	}
	raw := r.take(2 * n)
	u := make([]uint16, 0, n)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

type writer struct{ b []byte }

func (w *writer) u16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *writer) str(s string) {
	if s == "" {
		w.b = append(w.b, 0)
		return
	}
	u := utf16.Encode([]rune(s))
	if len(u) > 254 {
		u = u[:254]
	}
	w.b = append(w.b, byte(len(u)+1))
	for _, c := range u {
		w.u16(c)
	}
	w.u16(0)
}

type bufWriter struct{ b []byte }

func (w *bufWriter) Write(p []byte) (int, error) {
	if len(w.b)+len(p) > 64<<20 {
		return 0, errors.New("MTP dataset too large")
	}
	w.b = append(w.b, p...)
	return len(p), nil
}

func (s *Session) get(op uint16, params ...uint32) ([]byte, error) {
	var w bufWriter
	if _, err := s.do(op, params, nil, 0, &w); err != nil {
		return nil, err
	}
	return w.b, nil
}

// Storage is one storage area of the device (internal memory, SD card).
type Storage struct {
	ID          uint32
	Description string
	Label       string
	Capacity    uint64
	Free        uint64
	ReadOnly    bool
}

// Storages lists the device's storages. An Android phone that is locked (or
// hasn't allowed file access yet) returns none.
func (s *Session) Storages() ([]Storage, error) {
	b, err := s.get(opGetStorageIDs)
	if err != nil {
		return nil, err
	}
	r := &reader{b: b}
	n := r.u32()
	var out []Storage
	for i := uint32(0); i < n && !r.err; i++ {
		id := r.u32()
		if id&0xFFFF == 0 { // logical storage not present (empty card slot)
			continue
		}
		info, err := s.get(opGetStorageInfo, id)
		if err != nil {
			return nil, err
		}
		ir := &reader{b: info}
		ir.u16() // storage type
		ir.u16() // filesystem type
		access := ir.u16()
		st := Storage{ID: id, Capacity: ir.u64(), Free: ir.u64(), ReadOnly: access != 0}
		ir.u32() // free objects
		st.Description, st.Label = ir.str(), ir.str()
		out = append(out, st)
	}
	return out, nil
}

// Object is a file or folder.
type Object struct {
	Handle   uint32
	Storage  uint32
	Parent   uint32
	Name     string
	Size     uint64
	Folder   bool
	Format   uint16
	Modified time.Time
}

// List returns the objects directly under parent (RootParent for the top).
func (s *Session) List(storage, parent uint32) ([]Object, error) {
	b, err := s.get(opGetObjectHandles, storage, 0, parent)
	if err != nil {
		return nil, err
	}
	r := &reader{b: b}
	n := r.u32()
	out := make([]Object, 0, n)
	for i := uint32(0); i < n && !r.err; i++ {
		o, err := s.Info(r.u32())
		if err != nil {
			var me *Error
			if errors.As(err, &me) {
				continue // removed meanwhile
			}
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// Info returns one object's metadata.
func (s *Session) Info(h uint32) (Object, error) {
	b, err := s.get(opGetObjectInfo, h)
	if err != nil {
		return Object{}, err
	}
	return parseObjectInfo(h, b), nil
}

func parseObjectInfo(h uint32, b []byte) Object {
	r := &reader{b: b}
	o := Object{Handle: h}
	o.Storage = r.u32()
	o.Format = r.u16()
	r.u16() // protection
	o.Size = uint64(r.u32())
	r.take(2 + 4*6) // thumb format/size/w/h, image w/h/depth
	o.Parent = r.u32()
	assoc := r.u16()
	r.u32() // association desc
	r.u32() // sequence number
	o.Name = r.str()
	r.str() // capture date
	o.Modified = parseDate(r.str())
	o.Folder = o.Format == FormatAssociation || assoc == 1
	return o
}

// parseDate parses "YYYYMMDDThhmmss[.s][Z|±hhmm]" (local time when no zone).
func parseDate(s string) time.Time {
	if len(s) < 15 {
		return time.Time{}
	}
	t, err := time.ParseInLocation("20060102T150405", s[:15], time.Local)
	if err != nil {
		return time.Time{}
	}
	rest := s[15:]
	if i := strings.IndexAny(rest, "Z+-"); i >= 0 {
		rest = rest[i:]
		if rest == "Z" {
			return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		}
		if z, err := time.Parse("-0700", rest); err == nil {
			return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, z.Location())
		}
	}
	return t
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("20060102T150405")
}

// Get downloads an object into w.
func (s *Session) Get(h uint32, w io.Writer) error {
	_, err := s.do(opGetObject, []uint32{h}, nil, 0, w)
	return err
}

// FormatFor picks the object format by file extension (devices mostly go by
// the name anyway).
func FormatFor(name string) uint16 {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return FormatUndefined
	}
	switch strings.ToLower(name[i+1:]) {
	case "mp3":
		return FormatMP3
	case "wav":
		return FormatWAV
	case "txt":
		return FormatText
	case "jpg", "jpeg":
		return FormatJPEG
	}
	return FormatUndefined
}

func objectInfo(storage, parent uint32, format uint16, assoc uint16, name string, size int64, modified time.Time) []byte {
	sz := uint32(0xFFFFFFFF)
	if size < 0xFFFFFFFF {
		sz = uint32(size)
	}
	var w writer
	w.u32(storage)
	w.u16(format)
	w.u16(0)  // protection
	w.u32(sz) // compressed size
	w.u16(0)  // thumb format
	for range 6 {
		w.u32(0) // thumb size/w/h, image w/h/depth
	}
	w.u32(parent)
	w.u16(assoc) // association type (1 = generic folder)
	w.u32(0)     // association desc
	w.u32(0)     // sequence
	w.str(name)
	w.str("") // capture date
	w.str(formatDate(modified))
	w.str("") // keywords
	return w.b
}

func (s *Session) sendInfo(storage, parent uint32, info []byte) (uint32, error) {
	p, err := s.do(opSendObjectInfo, []uint32{storage, parent}, bytesReader(info), int64(len(info)), nil)
	if err != nil {
		return 0, err
	}
	if len(p) < 3 {
		return 0, fmt.Errorf("SendObjectInfo 응답에 핸들 없음")
	}
	return p[2], nil
}

// Send uploads size bytes from r as name under parent and returns its handle.
// On a failed data phase the handle of the incomplete object is returned too.
func (s *Session) Send(storage, parent uint32, name string, size int64, modified time.Time, r io.Reader) (uint32, error) {
	h, err := s.sendInfo(storage, parent, objectInfo(storage, parent, FormatFor(name), 0, name, size, modified))
	if err != nil {
		return 0, err
	}
	if _, err := s.do(opSendObject, nil, r, size, nil); err != nil {
		return h, err // the (incomplete) object may exist: caller cleans up
	}
	return h, nil
}

// Mkdir creates a folder under parent and returns its handle.
func (s *Session) Mkdir(storage, parent uint32, name string) (uint32, error) {
	return s.sendInfo(storage, parent, objectInfo(storage, parent, FormatAssociation, 1, name, 0, time.Time{}))
}

// Delete removes an object.
func (s *Session) Delete(h uint32) error {
	_, err := s.do(opDeleteObject, []uint32{h, 0}, nil, 0, nil)
	return err
}

type sliceReader struct{ b []byte }

func bytesReader(b []byte) *sliceReader { return &sliceReader{b} }
func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// IsWriterError reports a failure of the local writer during Get (the MTP
// session is still fine).
func IsWriterError(err error) bool {
	var we *writerError
	return errors.As(err, &we)
}
