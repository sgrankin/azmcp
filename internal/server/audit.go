package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var errAudit = errors.New("durable audit log is unavailable")

type Audit interface {
	Prepare() error
	Append(record any) error
}

type FileAudit struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	retained int
	file     *os.File
	bytes    int64
	closed   bool
}

func NewFileAudit(path string, maxBytes int64, retained int) (*FileAudit, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || maxBytes < 64*1024 || retained < 1 || retained > 100 {
		return nil, errAudit
	}
	return &FileAudit{path: path, maxBytes: maxBytes, retained: retained}, nil
}

func (a *FileAudit) open() error {
	if a.closed {
		return errAudit
	}
	if a.file != nil {
		return nil
	}
	parent := filepath.Dir(a.path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return errAudit
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errAudit
	}
	if err := regularOrAbsent(a.path); err != nil {
		return err
	}
	fd, err := unix.Open(a.path, unix.O_CREAT|unix.O_APPEND|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errAudit
	}
	f := os.NewFile(uintptr(fd), a.path)
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return errAudit
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return errAudit
	}
	a.file = f
	a.bytes = info.Size()
	return nil
}

func regularOrAbsent(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return errAudit
	}
	return nil
}

func (a *FileAudit) Prepare() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.open()
}

func (a *FileAudit) rotate() error {
	if err := a.file.Close(); err != nil {
		return errAudit
	}
	a.file = nil
	for i := a.retained; i >= 1; i-- {
		src := a.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", a.path, i-1)
		}
		dst := fmt.Sprintf("%s.%d", a.path, i)
		if err := regularOrAbsent(src); err != nil {
			return err
		}
		if _, err := os.Lstat(src); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return errAudit
		}
		if info, err := os.Lstat(dst); err == nil {
			if info.IsDir() {
				return errAudit
			}
			if err := os.Remove(dst); err != nil {
				return errAudit
			}
		} else if !os.IsNotExist(err) {
			return errAudit
		}
		if err := os.Rename(src, dst); err != nil {
			return errAudit
		}
	}
	a.bytes = 0
	return a.open()
}

func (a *FileAudit) Append(record any) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return errAudit
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errAudit
	}
	stamp, _ := json.Marshal(time.Now().UnixMilli())
	fields["timestampUnixMs"] = stamp
	data, err := json.Marshal(fields)
	if err != nil || len(data)+1 > 64*1024 {
		return errAudit
	}
	data = append(data, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.open(); err != nil {
		return err
	}
	if a.bytes > 0 && a.bytes+int64(len(data)) > a.maxBytes {
		if err = a.rotate(); err != nil {
			return err
		}
	}
	n, err := a.file.Write(data)
	if err != nil || n != len(data) {
		return errAudit
	}
	if err = a.file.Sync(); err != nil {
		return errAudit
	}
	a.bytes += int64(n)
	return nil
}

func (a *FileAudit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
}
