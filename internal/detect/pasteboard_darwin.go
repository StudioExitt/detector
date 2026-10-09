package detect

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// pasteboard wraps the macOS general pasteboard (NSPasteboard) through the
// Objective-C runtime via purego, so no cgo is needed. All methods must be
// called from a single goroutine locked to its OS thread.
type pasteboard struct {
	pb      objc.ID
	strType objc.ID // NSPasteboardTypeString ("public.utf8-plain-text"), retained
}

var (
	appKitOnce sync.Once
	appKitErr  error

	selNew             = objc.RegisterName("new")
	selRetain          = objc.RegisterName("retain")
	selRelease         = objc.RegisterName("release")
	selDrain           = objc.RegisterName("drain")
	selCount           = objc.RegisterName("count")
	selObjectAtIndex   = objc.RegisterName("objectAtIndex:")
	selAddObject       = objc.RegisterName("addObject:")
	selUTF8String      = objc.RegisterName("UTF8String")
	selStringWithUTF8  = objc.RegisterName("stringWithUTF8String:")
	selGeneralPB       = objc.RegisterName("generalPasteboard")
	selChangeCount     = objc.RegisterName("changeCount")
	selStringForType   = objc.RegisterName("stringForType:")
	selClearContents   = objc.RegisterName("clearContents")
	selSetStringForTyp = objc.RegisterName("setString:forType:")
	selPBItems         = objc.RegisterName("pasteboardItems")
	selTypes           = objc.RegisterName("types")
	selDataForType     = objc.RegisterName("dataForType:")
	selSetDataForType  = objc.RegisterName("setData:forType:")
	selWriteObjects    = objc.RegisterName("writeObjects:")
)

func openPasteboard() (*pasteboard, error) {
	appKitOnce.Do(func() {
		_, appKitErr = purego.Dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", purego.RTLD_GLOBAL|purego.RTLD_NOW)
	})
	if appKitErr != nil {
		return nil, fmt.Errorf("load AppKit: %w", appKitErr)
	}
	cls := objc.GetClass("NSPasteboard")
	if cls == 0 {
		return nil, fmt.Errorf("NSPasteboard class not found")
	}
	p := &pasteboard{}
	withPool(func() {
		p.pb = objc.ID(cls).Send(selGeneralPB)
		p.strType = nsString("public.utf8-plain-text").Send(selRetain)
	})
	if p.pb == 0 {
		return nil, fmt.Errorf("general pasteboard unavailable (no GUI login session?)")
	}
	return p, nil
}

func withPool(fn func()) {
	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(selNew)
	defer pool.Send(selDrain)
	fn()
}

// nsString returns an autoreleased NSString.
func nsString(s string) objc.ID {
	return objc.ID(objc.GetClass("NSString")).Send(selStringWithUTF8, s)
}

func (p *pasteboard) ChangeCount() int {
	return objc.Send[int](p.pb, selChangeCount)
}

// ReadString returns the plain-text content, if any.
func (p *pasteboard) ReadString() (s string, ok bool) {
	withPool(func() {
		str := p.pb.Send(selStringForType, p.strType)
		if str != 0 {
			s, ok = objc.Send[string](str, selUTF8String), true
		}
	})
	return s, ok
}

// WriteString replaces the pasteboard with plain text and returns the new change count.
func (p *pasteboard) WriteString(s string) int {
	withPool(func() {
		p.pb.Send(selClearContents)
		objc.Send[bool](p.pb, selSetStringForTyp, nsString(s), p.strType)
	})
	return p.ChangeCount()
}

// pbItem holds retained (type, data) pairs of one pasteboard item.
type pbItem struct {
	types []objc.ID
	datas []objc.ID
}

// Snapshot copies every item and representation (text, rich text, images,
// file URLs ...) so the canary test can put the user's clipboard back.
func (p *pasteboard) Snapshot() []pbItem {
	var out []pbItem
	withPool(func() {
		items := p.pb.Send(selPBItems)
		if items == 0 {
			return
		}
		for i := range objc.Send[int](items, selCount) {
			it := items.Send(selObjectAtIndex, i)
			types := it.Send(selTypes)
			var saved pbItem
			for j := range objc.Send[int](types, selCount) {
				t := types.Send(selObjectAtIndex, j)
				d := it.Send(selDataForType, t)
				if d == 0 {
					continue
				}
				saved.types = append(saved.types, t.Send(selRetain))
				saved.datas = append(saved.datas, d.Send(selRetain))
			}
			if len(saved.types) > 0 {
				out = append(out, saved)
			}
		}
	})
	return out
}

// Restore writes a snapshot back and releases it. Returns false if writing failed.
func (p *pasteboard) Restore(items []pbItem) bool {
	ok := true
	withPool(func() {
		p.pb.Send(selClearContents)
		if len(items) == 0 {
			return
		}
		arr := objc.ID(objc.GetClass("NSMutableArray")).Send(selNew)
		defer arr.Send(selRelease)
		for _, it := range items {
			pi := objc.ID(objc.GetClass("NSPasteboardItem")).Send(selNew)
			for k := range it.types {
				objc.Send[bool](pi, selSetDataForType, it.datas[k], it.types[k])
			}
			arr.Send(selAddObject, pi)
			pi.Send(selRelease)
		}
		ok = objc.Send[bool](p.pb, selWriteObjects, arr)
	})
	for _, it := range items {
		for k := range it.types {
			it.types[k].Send(selRelease)
			it.datas[k].Send(selRelease)
		}
	}
	return ok
}
