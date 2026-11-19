// Package usbfs browses and copies / moves files between PC folders, mounted
// USB disks and MTP devices (Android phones) for the web UI.
package usbfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"detector/internal/usbfs/mtp"
)

// Entry is a file or folder in a location.
type Entry struct {
	ID       string // path relative to the location root, or an MTP object handle
	Name     string
	Dir      bool
	Size     int64
	Modified time.Time
}

// Store is an opened location.
type Store interface {
	List(ctx context.Context, dir string) ([]Entry, error)
	Read(ctx context.Context, id string, w io.Writer) error
	// Write stores size bytes from r as name in dir.
	Write(ctx context.Context, dir, name string, size int64, modified time.Time, r io.Reader, overwrite bool) error
	// Mkdir creates folder name in dir, or returns the existing one; returns its id.
	Mkdir(ctx context.Context, dir, name string) (string, error)
	Delete(ctx context.Context, id string) error // files
	// RemoveDirIfEmpty deletes a folder only when nothing is left in it
	// (hidden files count, except OS junk like .DS_Store).
	RemoveDirIfEmpty(ctx context.Context, id string) (bool, error)
	Close() error
}

// junkFile: files the OS leaves in folders that don't keep them from being removed.
func junkFile(name string) bool {
	return name == ".DS_Store" || strings.HasPrefix(name, "._") || name == "Thumbs.db" || name == "desktop.ini"
}

var (
	ErrExists   = errors.New("같은 이름의 파일이 이미 있음")
	ErrBadPath  = errors.New("잘못된 경로")
	ErrNotFound = errors.New("위치를 찾을 수 없음")
	ErrBusy     = errors.New("다른 전송이 진행 중")
)

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Dir != es[j].Dir {
			return es[i].Dir
		}
		return strings.ToLower(es[i].Name) < strings.ToLower(es[j].Name)
	})
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

// ── local folders / mounted volumes ──

type localStore struct {
	root  *os.Root
	chown bool // files written under sudo are handed to SUDO_UID
}

func openLocal(dir string, chown bool) (*localStore, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &localStore{root: r, chown: chown}, nil
}

func relPath(p string) (string, error) {
	if p == "" {
		return ".", nil
	}
	c := path.Clean(p)
	if path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return "", ErrBadPath
	}
	for part := range strings.SplitSeq(c, "/") {
		if strings.HasPrefix(part, ".") && part != "." {
			return "", ErrBadPath // hidden files / folders (.ssh, .config ...) stay out of reach
		}
	}
	return c, nil
}

func (s *localStore) List(_ context.Context, dir string) ([]Entry, error) {
	d, err := relPath(dir)
	if err != nil {
		return nil, err
	}
	f, err := s.root.Open(d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		name := de.Name()
		if strings.HasPrefix(name, ".") || de.Type()&fs.ModeSymlink != 0 {
			continue // hidden files, macOS "._" forks, links that may leave the root
		}
		info, err := de.Info()
		if err != nil || !(info.IsDir() || info.Mode().IsRegular()) {
			continue
		}
		e := Entry{ID: path.Join(dir, name), Name: name, Dir: info.IsDir(), Modified: info.ModTime()}
		if !e.Dir {
			e.Size = info.Size()
		}
		out = append(out, e)
	}
	sortEntries(out)
	return out, nil
}

func (s *localStore) Read(_ context.Context, id string, w io.Writer) error {
	p, err := relPath(id)
	if err != nil {
		return err
	}
	f, err := s.root.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func (s *localStore) Write(_ context.Context, dir, name string, size int64, modified time.Time, r io.Reader, overwrite bool) error {
	d, err := relPath(dir)
	if err != nil || !validName(name) {
		return ErrBadPath
	}
	target := path.Join(d, name)
	if _, err := s.root.Lstat(target); err == nil && !overwrite {
		return ErrExists
	}
	tmp := path.Join(d, "."+name+".part")
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, r)
	if err == nil && n != size {
		err = fmt.Errorf("크기 불일치 (%d / %d bytes)", n, size)
	}
	if err == nil {
		err = f.Sync() // USB sticks: make sure it is on the disk before an eject
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.root.Rename(tmp, target)
	}
	if err != nil {
		_ = s.root.Remove(tmp)
		return err
	}
	if !modified.IsZero() {
		_ = s.root.Chtimes(target, modified, modified)
	}
	if s.chown {
		if uid, gid, ok := sudoIDs(); ok {
			_ = s.root.Lchown(target, uid, gid)
		}
	}
	return nil
}

func (s *localStore) Mkdir(_ context.Context, dir, name string) (string, error) {
	d, err := relPath(dir)
	if err != nil || !validName(name) || strings.HasPrefix(name, ".") {
		return "", ErrBadPath
	}
	target := path.Join(d, name)
	if st, err := s.root.Lstat(target); err == nil {
		if st.IsDir() {
			return target, nil
		}
		return "", ErrExists
	}
	if err := s.root.Mkdir(target, 0o755); err != nil {
		return "", err
	}
	if s.chown {
		if uid, gid, ok := sudoIDs(); ok {
			_ = s.root.Lchown(target, uid, gid)
		}
	}
	return target, nil
}

func (s *localStore) RemoveDirIfEmpty(_ context.Context, id string) (bool, error) {
	p, err := relPath(id)
	if err != nil || p == "." {
		return false, ErrBadPath
	}
	f, err := s.root.Open(p)
	if err != nil {
		return false, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if !junkFile(n) {
			return false, nil
		}
	}
	for _, n := range names {
		_ = s.root.Remove(path.Join(p, n))
	}
	return true, s.root.Remove(p)
}

func (s *localStore) Delete(_ context.Context, id string) error {
	p, err := relPath(id)
	if err != nil || p == "." {
		return ErrBadPath
	}
	return s.root.Remove(p)
}

func (s *localStore) Close() error { return s.root.Close() }

// sudoIDs: the invoking user when running under sudo.
func sudoIDs() (int, int, bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	return uid, gid, err1 == nil && err2 == nil
}

// homeDir: the invoking user's home under sudo, else the current user's.
func homeDir() string {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

func expandHome(p string) string {
	if p == "~" {
		return homeDir()
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return path.Join(homeDir(), rest)
	}
	return p
}

// ── MTP storage ──

type mtpStore struct {
	dev     mtp.Device
	storage uint32
	sess    *mtp.Session
	names   map[string]map[string]mtpName // dir -> name -> object (dirs listed so far)
}

type mtpName struct {
	h      uint32
	folder bool
}

func openMTP(dev mtp.Device, storage uint32) (*mtpStore, error) {
	sess, err := dev.Open()
	if err != nil {
		return nil, err
	}
	return &mtpStore{dev: dev, storage: storage, sess: sess, names: map[string]map[string]mtpName{}}, nil
}

// ensure reopens the session after a broken transfer.
func (s *mtpStore) ensure() error {
	if s.sess != nil && !s.sess.Broken() {
		return nil
	}
	if s.sess != nil {
		_ = s.sess.Close()
		s.sess = nil
	}
	sess, err := s.dev.Open()
	if err != nil {
		return err
	}
	s.sess = sess
	return nil
}

func parseHandle(id string) (uint32, error) {
	if id == "" {
		return mtp.RootParent, nil
	}
	v, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, ErrBadPath
	}
	return uint32(v), nil
}

func (s *mtpStore) List(_ context.Context, dir string) ([]Entry, error) {
	parent, err := parseHandle(dir)
	if err != nil {
		return nil, err
	}
	if err := s.ensure(); err != nil {
		return nil, err
	}
	objs, err := s.sess.List(s.storage, parent)
	if err != nil {
		return nil, err
	}
	names := map[string]mtpName{}
	out := make([]Entry, 0, len(objs))
	for _, o := range objs {
		if o.Storage != s.storage && o.Storage != 0 {
			continue
		}
		names[o.Name] = mtpName{o.Handle, o.Folder}
		if strings.HasPrefix(o.Name, ".") {
			continue
		}
		e := Entry{ID: strconv.FormatUint(uint64(o.Handle), 10), Name: o.Name, Dir: o.Folder, Modified: o.Modified}
		if !e.Dir {
			e.Size = int64(o.Size)
		}
		out = append(out, e)
	}
	s.names[dir] = names
	sortEntries(out)
	return out, nil
}

func (s *mtpStore) Read(_ context.Context, id string, w io.Writer) error {
	h, err := parseHandle(id)
	if err != nil || id == "" {
		return ErrBadPath
	}
	if err := s.ensure(); err != nil {
		return err
	}
	return s.sess.Get(h, w)
}

func (s *mtpStore) Write(ctx context.Context, dir, name string, size int64, modified time.Time, r io.Reader, overwrite bool) error {
	parent, err := parseHandle(dir)
	if err != nil || !validName(name) {
		return ErrBadPath
	}
	if _, ok := s.names[dir]; !ok {
		if _, err := s.List(ctx, dir); err != nil {
			return err
		}
	}
	if err := s.ensure(); err != nil {
		return err
	}
	if n, ok := s.names[dir][name]; ok {
		if !overwrite || n.folder {
			return ErrExists
		}
		if err := s.sess.Delete(n.h); err != nil {
			return fmt.Errorf("기존 파일 삭제 실패: %w", err)
		}
		delete(s.names[dir], name)
	}
	h, err := s.sess.Send(s.storage, parent, name, size, modified, r)
	if err != nil {
		if h != 0 && s.ensure() == nil {
			_ = s.sess.Delete(h) // remove the incomplete file
		}
		return err
	}
	s.names[dir][name] = mtpName{h, false}
	return nil
}

func (s *mtpStore) Mkdir(ctx context.Context, dir, name string) (string, error) {
	parent, err := parseHandle(dir)
	if err != nil || !validName(name) {
		return "", ErrBadPath
	}
	if _, ok := s.names[dir]; !ok {
		if _, err := s.List(ctx, dir); err != nil {
			return "", err
		}
	}
	if n, ok := s.names[dir][name]; ok {
		if n.folder {
			return strconv.FormatUint(uint64(n.h), 10), nil
		}
		return "", ErrExists
	}
	if err := s.ensure(); err != nil {
		return "", err
	}
	h, err := s.sess.Mkdir(s.storage, parent, name)
	if err != nil {
		return "", err
	}
	id := strconv.FormatUint(uint64(h), 10)
	s.names[dir][name] = mtpName{h, true}
	s.names[id] = map[string]mtpName{} // new and empty
	return id, nil
}

// RemoveDirIfEmpty: MTP deletes folders recursively, so check first that
// nothing (hidden files included) is left inside.
func (s *mtpStore) RemoveDirIfEmpty(_ context.Context, id string) (bool, error) {
	h, err := parseHandle(id)
	if err != nil || id == "" {
		return false, ErrBadPath
	}
	if err := s.ensure(); err != nil {
		return false, err
	}
	objs, err := s.sess.List(s.storage, h)
	if err != nil {
		return false, err
	}
	if len(objs) > 0 {
		return false, nil
	}
	return true, s.Delete(context.Background(), id)
}

func (s *mtpStore) Delete(_ context.Context, id string) error {
	h, err := parseHandle(id)
	if err != nil || id == "" {
		return ErrBadPath
	}
	if err := s.ensure(); err != nil {
		return err
	}
	if err := s.sess.Delete(h); err != nil {
		return err
	}
	delete(s.names, id)
	for _, m := range s.names {
		for n, v := range m {
			if v.h == h {
				delete(m, n)
			}
		}
	}
	return nil
}

func (s *mtpStore) Close() error {
	if s.sess == nil {
		return nil
	}
	err := s.sess.Close()
	s.sess = nil
	return err
}
