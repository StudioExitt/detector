package mtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

// fakeDevice is an in-memory MTP responder speaking over a Transport.
type fakeDevice struct {
	mp      int
	in      [][]byte // queued packets for BulkIn
	out     []byte   // pending bulk-out stream
	objects map[uint32]*fakeObj
	next    uint32
	pending *fakeObj // after SendObjectInfo
	zlps    int
}

type fakeObj struct {
	parent uint32
	name   string
	data   []byte
	folder bool
}

func newFake() *fakeDevice {
	return &fakeDevice{mp: 512, next: 10, objects: map[uint32]*fakeObj{
		1: {parent: RootParent, name: "Music", folder: true},
		2: {parent: 1, name: "a.mp3", data: bytes.Repeat([]byte{7}, 2000)},
		3: {parent: 1, name: "한글.mp3", data: bytes.Repeat([]byte{9}, 1024-12)}, // packet aligned with header
	}}
}

func (f *fakeDevice) MaxPacket() int { return f.mp }
func (f *fakeDevice) BufSize() int   { return 4096 }
func (f *fakeDevice) Close() error   { return nil }

func (f *fakeDevice) BulkIn(p []byte, _ time.Duration) (int, error) {
	if len(f.in) == 0 {
		return 0, errors.New("nothing to read")
	}
	pk := f.in[0]
	n := copy(p, pk)
	if n < len(pk) {
		f.in[0] = pk[n:]
	} else {
		f.in = f.in[1:]
	}
	return n, nil
}

// queue sends b to the host the way a device would: in max-packet pieces,
// with a ZLP when the container ends on a packet boundary.
func (f *fakeDevice) queue(b []byte) {
	f.in = append(f.in, b)
	if len(b)%f.mp == 0 {
		f.in = append(f.in, []byte{})
	}
}

func container(typ, code uint16, tid uint32, payload []byte) []byte {
	b := make([]byte, hdrLen, hdrLen+len(payload))
	putHeader(b, uint32(hdrLen+len(payload)), typ, code, tid)
	return append(b, payload...)
}

func (f *fakeDevice) respond(tid uint32, code uint16, params ...uint32) {
	var w writer
	for _, p := range params {
		w.u32(p)
	}
	f.queue(container(typeResponse, code, tid, w.b))
}

func (f *fakeDevice) BulkOut(p []byte, _ time.Duration) (int, error) {
	if len(p) == 0 {
		f.zlps++
		return 0, nil
	}
	f.out = append(f.out, p...)
	for len(f.out) >= hdrLen {
		length := int(binary.LittleEndian.Uint32(f.out))
		if len(f.out) < length {
			break
		}
		c := f.out[:length]
		f.out = f.out[length:]
		f.handle(c)
	}
	return len(p), nil
}

func (f *fakeDevice) handle(c []byte) {
	typ := binary.LittleEndian.Uint16(c[4:])
	code := binary.LittleEndian.Uint16(c[6:])
	tid := binary.LittleEndian.Uint32(c[8:])
	r := &reader{b: c[hdrLen:]}
	if typ == typeData {
		switch code {
		case opSendObjectInfo:
			o := parseObjectInfo(0, c[hdrLen:])
			f.pending = &fakeObj{parent: o.Parent, name: o.Name, folder: o.Folder}
			f.next++
			f.objects[f.next] = f.pending
			f.respond(tid, rcOK, 0x10001, o.Parent, f.next)
		case opSendObject:
			f.pending.data = append([]byte(nil), c[hdrLen:]...)
			f.respond(tid, rcOK)
		}
		return
	}
	switch code {
	case opSendObjectInfo, opSendObject: // answered after the data phase
	case opOpenSession, opCloseSession:
		f.respond(tid, rcOK)
	case opGetStorageIDs:
		var w writer
		w.u32(2)
		w.u32(0x10001)
		w.u32(0x20000) // empty slot
		f.queue(container(typeData, code, tid, w.b))
		f.respond(tid, rcOK)
	case opGetStorageInfo:
		var w writer
		w.u16(3)
		w.u16(2)
		w.u16(0)
		w.b = binary.LittleEndian.AppendUint64(w.b, 64<<30)
		w.b = binary.LittleEndian.AppendUint64(w.b, 10<<30)
		w.u32(0)
		w.str("내부 저장소")
		w.str("")
		f.queue(container(typeData, code, tid, w.b))
		f.respond(tid, rcOK)
	case opGetObjectHandles:
		r.u32()
		r.u32()
		parent := r.u32()
		var hs []uint32
		for h, o := range f.objects {
			if o.parent == parent {
				hs = append(hs, h)
			}
		}
		var w writer
		w.u32(uint32(len(hs)))
		for _, h := range hs {
			w.u32(h)
		}
		f.queue(container(typeData, code, tid, w.b))
		f.respond(tid, rcOK)
	case opGetObjectInfo:
		h := r.u32()
		o, ok := f.objects[h]
		if !ok {
			f.respond(tid, 0x2009)
			return
		}
		var w writer
		w.u32(0x10001)
		if o.folder {
			w.u16(FormatAssociation)
		} else {
			w.u16(FormatMP3)
		}
		w.u16(0)
		w.u32(uint32(len(o.data)))
		w.u16(0)
		for range 6 {
			w.u32(0)
		}
		w.u32(o.parent)
		w.u16(0)
		w.u32(0)
		w.u32(0)
		w.str(o.name)
		w.str("")
		w.str("20260102T030405")
		w.str("")
		f.queue(container(typeData, code, tid, w.b))
		f.respond(tid, rcOK)
	case opGetObject:
		o := f.objects[r.u32()]
		f.queue(container(typeData, code, tid, o.data))
		f.respond(tid, rcOK)
	case opDeleteObject:
		h := r.u32()
		if _, ok := f.objects[h]; !ok {
			f.respond(tid, 0x2009)
			return
		}
		delete(f.objects, h)
		f.respond(tid, rcOK)
	default:
		f.respond(tid, 0x2005)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	f := newFake()
	s, err := OpenSession(f)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.Storages()
	if err != nil || len(st) != 1 || st[0].Description != "내부 저장소" || st[0].Free != 10<<30 {
		t.Fatalf("storages = %+v, %v", st, err)
	}
	root, err := s.List(st[0].ID, RootParent)
	if err != nil || len(root) != 1 || !root[0].Folder || root[0].Name != "Music" {
		t.Fatalf("root = %+v, %v", root, err)
	}
	files, err := s.List(st[0].ID, 1)
	if err != nil || len(files) != 2 {
		t.Fatalf("files = %+v, %v", files, err)
	}
	for _, o := range files {
		var buf bytes.Buffer
		if err := s.Get(o.Handle, &buf); err != nil {
			t.Fatalf("get %s: %v", o.Name, err)
		}
		if !bytes.Equal(buf.Bytes(), f.objects[o.Handle].data) || uint64(buf.Len()) != o.Size {
			t.Fatalf("get %s: %d bytes", o.Name, buf.Len())
		}
		if o.Modified.Year() != 2026 {
			t.Fatalf("modified = %v", o.Modified)
		}
	}

	// upload sizes around packet boundaries (header + data = 512 needs a ZLP)
	for _, size := range []int{0, 500, 4096*3 + 7, 512 - hdrLen} {
		data := bytes.Repeat([]byte{byte(size)}, size)
		zlps := f.zlps
		h, err := s.Send(st[0].ID, 1, "새 노래.mp3", int64(size), time.Now(), bytes.NewReader(data))
		if err != nil {
			t.Fatalf("send %d: %v", size, err)
		}
		if o := f.objects[h]; o == nil || !bytes.Equal(o.data, data) || o.name != "새 노래.mp3" || o.parent != 1 {
			t.Fatalf("send %d: stored %+v", size, o)
		}
		if (size+hdrLen)%512 == 0 && f.zlps == zlps {
			t.Fatalf("send %d: no ZLP", size)
		}
		if err := s.Delete(h); err != nil {
			t.Fatal(err)
		}
	}

	dh, err := s.Mkdir(st[0].ID, 1, "앨범")
	if err != nil {
		t.Fatal(err)
	}
	if o := f.objects[dh]; o == nil || !o.folder || o.name != "앨범" || o.parent != 1 {
		t.Fatalf("mkdir stored %+v", o)
	}
	if objs, err := s.List(st[0].ID, 1); err != nil || len(objs) != 3 {
		t.Fatalf("after mkdir: %+v %v", objs, err)
	}

	var me *Error
	if err := s.Delete(999); !errors.As(err, &me) || me.Code != 0x2009 || s.Broken() {
		t.Fatalf("delete missing: %v broken=%v", err, s.Broken())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

func TestGetWriterErrorKeepsSession(t *testing.T) {
	f := newFake()
	s, err := OpenSession(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Get(2, failWriter{}); !IsWriterError(err) {
		t.Fatalf("err = %v", err)
	}
	if s.Broken() {
		t.Fatal("session broken after a local write error")
	}
	var buf bytes.Buffer
	if err := s.Get(2, &buf); err != nil || buf.Len() != 2000 {
		t.Fatalf("get after failure: %v %d", err, buf.Len())
	}
}

func TestShortSourceBreaksSession(t *testing.T) {
	s, err := OpenSession(newFake())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Send(0x10001, 1, "x.mp3", 100, time.Time{}, bytes.NewReader(make([]byte, 10)))
	if !errors.Is(err, ErrBroken) || !s.Broken() {
		t.Fatalf("err = %v broken=%v", err, s.Broken())
	}
}

func TestStrings(t *testing.T) {
	var w writer
	w.str("")
	w.str("노래 1.mp3")
	r := &reader{b: w.b}
	if a, b := r.str(), r.str(); a != "" || b != "노래 1.mp3" || r.err {
		t.Fatalf("%q %q", a, b)
	}
	if FormatFor("A.MP3") != FormatMP3 || FormatFor("x") != FormatUndefined {
		t.Fatal("format")
	}
	if d := parseDate("20260102T030405Z"); d.Hour() != 3 || d.Location() != time.UTC {
		t.Fatal(d)
	}
}
