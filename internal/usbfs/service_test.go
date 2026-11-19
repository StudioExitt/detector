package usbfs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"detector/internal/config"
)

func waitJob(t *testing.T, s *Service, id int) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, j := range s.Jobs() {
			if j.ID == id && j.State != JobRunning {
				return j
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return Job{}
}

func TestLocalTransfer(t *testing.T) {
	pc, usb := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(pc, "a.mp3"), []byte("aaaa"), 0o644)
	os.WriteFile(filepath.Join(pc, "b.MP3"), []byte("bb"), 0o644)
	os.WriteFile(filepath.Join(pc, "note.txt"), []byte("x"), 0o644)
	os.Mkdir(filepath.Join(pc, "sub"), 0o755)
	os.Mkdir(filepath.Join(usb, "Music"), 0o755)
	os.WriteFile(filepath.Join(usb, "Music", "b.MP3"), []byte("old"), 0o644)

	var mu sync.Mutex
	var self uint64
	var records []string
	s := New(config.TransferConfig{LocalDirs: []string{pc}}, Deps{
		Volumes: func() []Volume {
			return []Volume{{ID: "disk9s1", Disk: "disk9", Name: "STICK", MountPoint: usb}}
		},
		SelfWrite: func(disk string, n uint64) {
			mu.Lock()
			defer mu.Unlock()
			if disk == "disk9" {
				self += n
			}
		},
		Record: func(_ context.Context, target, detail string, ok bool) {
			mu.Lock()
			defer mu.Unlock()
			records = append(records, target+"|"+detail)
		},
	})
	ctx := context.Background()

	l, err := s.List(ctx, "pc:0", "", []string{"mp3"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range l.Entries {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "sub,a.mp3,b.MP3" {
		t.Fatalf("list = %v", names)
	}
	if _, err := s.List(ctx, "pc:0", "../..", nil); err == nil {
		t.Fatal("listing outside the root must fail")
	}
	os.MkdirAll(filepath.Join(pc, ".ssh", "keys"), 0o700)
	for _, d := range []string{".ssh", ".ssh/keys", "sub/../.ssh"} {
		if _, err := s.List(ctx, "pc:0", d, nil); err == nil {
			t.Fatalf("hidden folder %q must not be listable", d)
		}
	}

	// move: b.MP3 exists at the destination -> fails without overwrite; the empty folder moves too
	j, err := s.Start(ctx, Request{From: "pc:0", Items: []string{"a.mp3", "b.MP3", "sub"}, To: "vol:disk9s1", ToDir: "Music", Move: true})
	if err != nil {
		t.Fatal(err)
	}
	j = waitJob(t, s, j.ID)
	if j.Done != 1 || j.Failed != 1 || j.Folders != 1 || j.State != JobDone {
		t.Fatalf("job = %+v", j)
	}
	if b, _ := os.ReadFile(filepath.Join(usb, "Music", "a.mp3")); string(b) != "aaaa" {
		t.Fatalf("copied = %q", b)
	}
	if _, err := os.Stat(filepath.Join(pc, "a.mp3")); !os.IsNotExist(err) {
		t.Fatal("source not removed after move")
	}
	if b, _ := os.ReadFile(filepath.Join(usb, "Music", "b.MP3")); string(b) != "old" {
		t.Fatal("existing file overwritten")
	}
	if st, err := os.Stat(filepath.Join(usb, "Music", "sub")); err != nil || !st.IsDir() {
		t.Fatal("folder not created at the destination")
	}
	if _, err := os.Stat(filepath.Join(pc, "sub")); !os.IsNotExist(err) {
		t.Fatal("moved empty folder still at the source")
	}

	// overwrite
	j, err = s.Start(ctx, Request{From: "pc:0", Items: []string{"b.MP3"}, To: "vol:disk9s1", ToDir: "Music", Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if j = waitJob(t, s, j.ID); j.Done != 1 {
		t.Fatalf("job = %+v", j)
	}
	if b, _ := os.ReadFile(filepath.Join(usb, "Music", "b.MP3")); string(b) != "bb" {
		t.Fatalf("overwritten = %q", b)
	}
	if _, err := os.Stat(filepath.Join(pc, "b.MP3")); err != nil {
		t.Fatal("copy removed the source")
	}
	if left, _ := filepath.Glob(filepath.Join(usb, "Music", ".*.part")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}

	// back from the volume to the PC
	j, err = s.Start(ctx, Request{From: "vol:disk9s1", FromDir: "Music", Items: []string{"Music/a.mp3"}, To: "pc:0"})
	if err != nil {
		t.Fatal(err)
	}
	if j = waitJob(t, s, j.ID); j.Done != 1 {
		t.Fatalf("job = %+v", j)
	}
	if b, _ := os.ReadFile(filepath.Join(pc, "a.mp3")); string(b) != "aaaa" {
		t.Fatalf("copied back = %q", b)
	}

	mu.Lock()
	defer mu.Unlock()
	if self != 6 {
		t.Fatalf("self-written bytes = %d", self)
	}
	if len(records) != 3 || !strings.Contains(records[0], "이동 1개") {
		t.Fatalf("records = %v", records)
	}

	if _, err := s.Start(ctx, Request{From: "pc:0", Items: []string{"x"}, To: "pc:0"}); err == nil {
		t.Fatal("same location must be rejected")
	}
	if _, err := s.Start(ctx, Request{From: "pc:0", Items: []string{"x"}, To: "vol:nope"}); err == nil {
		t.Fatal("unknown location must be rejected")
	}
}

func TestFolderTransfer(t *testing.T) {
	pc, usb := t.TempDir(), t.TempDir()
	w := func(p, v string) {
		os.MkdirAll(filepath.Dir(filepath.Join(pc, p)), 0o755)
		os.WriteFile(filepath.Join(pc, p), []byte(v), 0o644)
	}
	w("Album/1.mp3", "one")
	w("Album/cover.jpg", "jpg")
	w("Album/.DS_Store", "junk")
	w("Album/CD2/2.mp3", "two")
	w("Album/CD2/.DS_Store", "junk")
	w("Album/Scans/back.jpg", "jpg") // no mp3: not created with the filter
	w("Album/Hidden/3.mp3", "three")
	w("Album/Hidden/.keep", "keep") // real hidden file: folder must stay
	os.MkdirAll(filepath.Join(usb, "Album", "CD2"), 0o755) // existing folders are merged

	s := New(config.TransferConfig{LocalDirs: []string{pc, usb}}, Deps{})
	ctx := context.Background()
	j, err := s.Start(ctx, Request{From: "pc:0", Items: []string{"Album"}, To: "pc:1", Move: true, Ext: []string{"mp3"}})
	if err != nil {
		t.Fatal(err)
	}
	j = waitJob(t, s, j.ID)
	if j.Files != 3 || j.Done != 3 || j.Failed != 0 || j.Folders != 3 || j.State != JobDone {
		t.Fatalf("job = %+v", j)
	}
	for p, v := range map[string]string{"Album/1.mp3": "one", "Album/CD2/2.mp3": "two", "Album/Hidden/3.mp3": "three"} {
		if b, _ := os.ReadFile(filepath.Join(usb, p)); string(b) != v {
			t.Fatalf("%s = %q", p, b)
		}
	}
	if _, err := os.Stat(filepath.Join(usb, "Album", "Scans")); !os.IsNotExist(err) {
		t.Fatal("folder without mp3 was created")
	}
	if _, err := os.Stat(filepath.Join(pc, "Album", "CD2")); !os.IsNotExist(err) {
		t.Fatal("emptied source folder (only junk left) not removed")
	}
	for _, p := range []string{"Album/cover.jpg", "Album/Scans/back.jpg", "Album/Hidden/.keep"} {
		if _, err := os.Stat(filepath.Join(pc, p)); err != nil {
			t.Fatalf("%s must stay at the source: %v", p, err)
		}
	}
}
