// Package artifact stores private, create-only JSON artifacts in bounded namespaces.
package artifact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pierrec/lz4/v4"
	"golang.org/x/sys/unix"
)

const (
	MaxArtifactBytes      = 480 * 1024
	MaxStreamLogicalBytes = 64 * 1024 * 1024
	MaxStreamStoredBytes  = 65 * 1024 * 1024
	MaxAppendBytes        = 400 * 1024
	MaxContextFiles       = 32
	MaxContextBytes       = 128 * 1024 * 1024
	MaxRootFiles          = 256
	MaxRootBytes          = 512 * 1024 * 1024
	lockName              = ".azmcp.lock"
	lockContent           = "azmcp-artifacts-v1\n"
)

var (
	ErrUnsafe        = errors.New("artifact storage path is unsafe")
	ErrClosed        = errors.New("artifact storage is closed")
	ErrExists        = errors.New("artifact destination already exists")
	ErrQuota         = errors.New("artifact storage quota exceeded")
	ErrMismatch      = errors.New("artifact ownership mismatch")
	ErrInUse         = errors.New("artifact root is already in use")
	ErrInvalidName   = errors.New("artifact file name is invalid")
	ErrValueTooLarge = errors.New("artifact value exceeds its encoded size limit")
)

type Limits struct {
	ArtifactBytes, StreamLogicalBytes, StreamStoredBytes int64
	ContextFiles, RootFiles                              int
	ContextBytes, RootBytes                              int64
}

func DefaultLimits() Limits {
	return Limits{MaxArtifactBytes, MaxStreamLogicalBytes, MaxStreamStoredBytes, MaxContextFiles, MaxRootFiles, MaxContextBytes, MaxRootBytes}
}

func (l Limits) validate() error {
	d := DefaultLimits()
	if l.ArtifactBytes <= 0 || l.ArtifactBytes > d.ArtifactBytes || l.StreamLogicalBytes <= 0 || l.StreamLogicalBytes > d.StreamLogicalBytes || l.StreamStoredBytes <= 0 || l.StreamStoredBytes > d.StreamStoredBytes || l.ContextFiles <= 0 || l.ContextFiles > d.ContextFiles || l.RootFiles <= 0 || l.RootFiles > d.RootFiles || l.ContextBytes <= 0 || l.ContextBytes > d.ContextBytes || l.RootBytes <= 0 || l.RootBytes > d.RootBytes || l.ArtifactBytes > l.ContextBytes || l.ArtifactBytes > l.RootBytes || l.ContextFiles > l.RootFiles || l.ContextBytes > l.RootBytes {
		return errors.New("artifact storage limits are invalid")
	}
	return nil
}

type Receipt struct {
	Path            string `json:"path"`
	Bytes           int64  `json:"bytes"`
	SHA256          string `json:"sha256"`
	LogicalBytes    int64  `json:"logicalBytes"`
	ContentEncoding string `json:"contentEncoding,omitempty"`
	MediaType       string `json:"mediaType"`
	Sensitivity     string `json:"sensitivity"`
}

type identity struct{ dev, ino uint64 }
type Namespace struct {
	name  string
	store *Store
}
type usage struct {
	files int
	bytes int64
}

type Store struct {
	mu              sync.Mutex
	root            string
	directory, lock *os.File
	rootID, lockID  identity
	limits          Limits
	turns           map[*Turn]bool
	namespaces      map[string]identity
	closed          bool
}

func randomName(prefix string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func fileID(stat *unix.Stat_t) identity { return identity{uint64(stat.Dev), uint64(stat.Ino)} }

func private(stat *unix.Stat_t, directory bool) bool {
	kind := uint32(unix.S_IFREG)
	forbidden := uint16(0177)
	if directory {
		kind = unix.S_IFDIR
		forbidden = 0077
	}
	return uint32(stat.Mode)&unix.S_IFMT == kind && uint16(stat.Mode)&forbidden == 0 && stat.Uid == uint32(os.Geteuid())
}

// Walk from a trusted descriptor so replacing any path component cannot redirect an operation.
func openDirectory(path string, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(os.PathSeparator) {
		return nil, ErrUnsafe
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(fd, part, 0700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				unix.Close(fd)
				return nil, mkdirErr
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsafe, openErr)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

func statFD(file *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstat(int(file.Fd()), &stat)
	return stat, err
}
func statAt(directory *os.File, name string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return stat, err
}
func openAt(directory *os.File, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func entries(directory *os.File) ([]os.DirEntry, error) {
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), directory.Name())
	defer file.Close()
	return file.ReadDir(-1)
}

func NewStore(root string, limits Limits) (*Store, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, ErrUnsafe
	}
	return &Store{root: root, limits: limits, turns: make(map[*Turn]bool), namespaces: make(map[string]identity)}, nil
}

func (s *Store) acquire(create bool) error {
	if s.closed {
		return ErrClosed
	}
	if s.lock != nil {
		return s.checkHeld()
	}
	directory, err := openDirectory(s.root, create)
	if err != nil {
		return err
	}
	fail := func(err error) error { directory.Close(); return err }
	stat, err := statFD(directory)
	if err != nil || !private(&stat, true) || (s.rootID != (identity{}) && s.rootID != fileID(&stat)) {
		return fail(ErrUnsafe)
	}
	existing, err := entries(directory)
	if err != nil {
		return fail(err)
	}
	if len(existing) != 0 {
		if _, err = statAt(directory, lockName); err != nil {
			return fail(ErrUnsafe)
		}
	}
	flags := unix.O_RDWR
	if create {
		flags |= unix.O_CREAT
	}
	lock, err := openAt(directory, lockName, flags)
	if err != nil {
		return fail(err)
	}
	lockStat, err := statFD(lock)
	if err != nil || !private(&lockStat, false) || (s.lockID != (identity{}) && s.lockID != fileID(&lockStat)) {
		lock.Close()
		return fail(ErrUnsafe)
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			err = ErrInUse
		}
		return fail(err)
	}
	release := func(err error) error { lock.Close(); return fail(err) }
	content, err := io.ReadAll(io.LimitReader(lock, int64(len(lockContent)+1)))
	if err != nil {
		return release(err)
	}
	if len(content) == 0 && len(existing) == 0 {
		if _, err = lock.WriteAt([]byte(lockContent), 0); err == nil {
			err = lock.Sync()
		}
		if err != nil {
			return release(err)
		}
	} else if string(content) != lockContent {
		return release(ErrUnsafe)
	}
	s.directory, s.lock, s.rootID, s.lockID = directory, lock, fileID(&stat), fileID(&lockStat)
	if _, _, err = s.scan("", true); err != nil {
		s.directory, s.lock = nil, nil
		return release(err)
	}
	return nil
}

func (s *Store) releaseIdle() error {
	for turn := range s.turns {
		if len(turn.stages) != 0 || len(turn.streams) != 0 {
			return nil
		}
	}
	var result error
	for turn := range s.turns {
		if turn.directory != nil {
			result = errors.Join(result, turn.directory.Close())
			turn.directory = nil
		}
	}
	if s.directory != nil {
		for name, id := range s.namespaces {
			stat, err := statAt(s.directory, name)
			if err != nil || !private(&stat, true) || fileID(&stat) != id {
				result = errors.Join(result, ErrUnsafe)
				continue
			}
			if err = unix.Unlinkat(int(s.directory.Fd()), name, unix.AT_REMOVEDIR); err == nil {
				delete(s.namespaces, name)
				result = errors.Join(result, s.directory.Sync())
			} else if !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
				result = errors.Join(result, err)
			}
		}
	}
	if s.lock != nil {
		result = errors.Join(result, s.lock.Close())
		s.lock = nil
	}
	if s.directory != nil {
		result = errors.Join(result, s.directory.Close())
		s.directory = nil
	}
	return result
}

func validOpaque(name, prefix string) bool {
	suffix := strings.TrimPrefix(name, prefix)
	if !strings.HasPrefix(name, prefix) || len(suffix) != 64 {
		return false
	}
	for _, c := range suffix {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func fileFormat(name string) (compression, format string, err error) {
	if len(name) == 0 || len(name) > 128 {
		return "", "", ErrInvalidName
	}
	stem := name
	compression = "identity"
	if strings.HasSuffix(stem, ".lz4") {
		compression = "lz4"
		stem = strings.TrimSuffix(stem, ".lz4")
	}
	if strings.HasSuffix(stem, ".jsonl") {
		format = "jsonLines"
		stem = strings.TrimSuffix(stem, ".jsonl")
	} else if strings.HasSuffix(stem, ".json") {
		format = "jsonArray"
		stem = strings.TrimSuffix(stem, ".json")
	} else {
		return "", "", ErrInvalidName
	}
	if stem == "" {
		return "", "", ErrInvalidName
	}
	for _, c := range stem {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", "", ErrInvalidName
		}
	}
	return compression, format, nil
}

func (s *Store) checkHeld() error {
	if s.closed {
		return ErrClosed
	}
	current, err := openDirectory(s.root, false)
	if err != nil {
		return ErrUnsafe
	}
	defer current.Close()
	stat, err := statFD(current)
	if err != nil || !private(&stat, true) || fileID(&stat) != s.rootID {
		return ErrUnsafe
	}
	lockStat, err := statAt(s.directory, lockName)
	if err != nil || !private(&lockStat, false) || fileID(&lockStat) != s.lockID {
		return ErrUnsafe
	}
	data := make([]byte, len(lockContent)+1)
	n, err := s.lock.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrUnsafe
	}
	if string(data[:n]) != lockContent {
		return ErrUnsafe
	}
	return nil
}

func (s *Store) openNamespace(ns Namespace) (*os.File, error) {
	id, exists := s.namespaces[ns.name]
	if ns.store != s || !exists || !validOpaque(ns.name, "ctx_") || id == (identity{}) {
		return nil, ErrMismatch
	}
	directory, err := openAt(s.directory, ns.name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, ErrUnsafe
	}
	stat, err := statFD(directory)
	if err != nil || !private(&stat, true) || fileID(&stat) != id {
		directory.Close()
		return nil, ErrUnsafe
	}
	return directory, nil
}

func (s *Store) AllocateNamespace() (Namespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Namespace{}, ErrClosed
	}
	name, err := randomName("ctx_")
	if err != nil {
		return Namespace{}, err
	}
	return Namespace{name, s}, nil
}

func (s *Store) BeginTurn(ctx context.Context, ns Namespace) (*Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, ErrClosed
	}
	if ns.store != s || !validOpaque(ns.name, "ctx_") {
		return nil, ErrMismatch
	}
	t := &Turn{store: s, namespace: ns, ctx: ctx, streams: make(map[string]*stream)}
	s.turns[t] = true
	return t, nil
}

func (s *Store) scan(namespace string, scavenge bool) (usage, usage, error) {
	var root, current usage
	dirs, err := entries(s.directory)
	if err != nil {
		return root, current, err
	}
	for _, entry := range dirs {
		name := entry.Name()
		if name == lockName {
			continue
		}
		if !validOpaque(name, "ctx_") {
			return root, current, ErrUnsafe
		}
		directory, err := openAt(s.directory, name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return root, current, ErrUnsafe
		}
		stat, err := statFD(directory)
		if err != nil || !private(&stat, true) {
			directory.Close()
			return root, current, ErrUnsafe
		}
		files, err := entries(directory)
		if err != nil {
			directory.Close()
			return root, current, err
		}
		var contextUsage usage
		for _, entry := range files {
			filename := entry.Name()
			stat, err := statAt(directory, filename)
			if err != nil || !private(&stat, false) {
				directory.Close()
				return root, current, ErrUnsafe
			}
			if strings.HasPrefix(filename, ".tmp_") {
				if !validOpaque(filename, ".tmp_") {
					directory.Close()
					return root, current, ErrUnsafe
				}
				if scavenge {
					if err = unix.Unlinkat(int(directory.Fd()), filename, 0); err != nil {
						directory.Close()
						return root, current, err
					}
					continue
				}
			} else if _, _, err = fileFormat(filename); err != nil {
				directory.Close()
				return root, current, err
			}
			contextUsage.files++
			contextUsage.bytes += stat.Size
		}
		directory.Close()
		root.files += contextUsage.files
		root.bytes += contextUsage.bytes
		if name == namespace {
			current = contextUsage
		}
	}
	return root, current, nil
}

func (s *Store) capacity(ns Namespace, files int, bytes int64) error {
	root, current, err := s.scan(ns.name, false)
	if err != nil {
		return err
	}
	if current.files+files > s.limits.ContextFiles || current.bytes+bytes > s.limits.ContextBytes || root.files+files > s.limits.RootFiles || root.bytes+bytes > s.limits.RootBytes {
		return ErrQuota
	}
	return nil
}

func (s *Store) Read(ctx context.Context, ns Namespace, name string) ([]byte, Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, Receipt{}, err
	}
	defer s.releaseIdle()
	if err := s.acquire(false); err != nil {
		return nil, Receipt{}, err
	}
	compression, format, err := fileFormat(name)
	if err != nil {
		return nil, Receipt{}, err
	}
	directory, err := s.openNamespace(ns)
	if err != nil {
		return nil, Receipt{}, err
	}
	defer directory.Close()
	file, err := openAt(directory, name, unix.O_RDONLY)
	if err != nil {
		return nil, Receipt{}, err
	}
	defer file.Close()
	stat, err := statFD(file)
	if err != nil || !private(&stat, false) {
		return nil, Receipt{}, ErrUnsafe
	}
	if stat.Size > s.limits.StreamStoredBytes {
		return nil, Receipt{}, ErrValueTooLarge
	}
	hash := sha256.New()
	stored := io.TeeReader(file, hash)
	var source io.Reader = stored
	if compression == "lz4" {
		var header [7]byte
		if _, err = io.ReadFull(file, header[:]); err != nil {
			return nil, Receipt{}, err
		}
		if header[0] != 0x04 || header[1] != 0x22 || header[2] != 0x4d || header[3] != 0x18 || header[4]&0x04 == 0 {
			return nil, Receipt{}, ErrUnsafe
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return nil, Receipt{}, err
		}
		source = lz4.NewReader(stored)
	}
	logical, err := readBounded(ctx, source, s.limits.StreamLogicalBytes)
	if err != nil {
		return nil, Receipt{}, err
	}
	after, err := statAt(directory, name)
	if err != nil || fileID(&after) != fileID(&stat) || after.Size != stat.Size {
		return nil, Receipt{}, ErrMismatch
	}
	if err = ctx.Err(); err != nil {
		return nil, Receipt{}, err
	}
	return logical, receipt(s.root, ns.name, name, stat.Size, int64(len(logical)), hex.EncodeToString(hash.Sum(nil)), compression, format), nil
}

func (s *Store) Delete(ctx context.Context, ns Namespace, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	defer s.releaseIdle()
	if err := s.acquire(false); err != nil {
		return err
	}
	if _, _, err := fileFormat(name); err != nil {
		return err
	}
	directory, err := s.openNamespace(ns)
	if err != nil {
		return err
	}
	defer directory.Close()
	for t := range s.turns {
		if t.namespace == ns {
			for _, stage := range t.stages {
				if stage.name == name {
					return ErrExists
				}
			}
			for _, stream := range t.streams {
				if stream.stage.name == name {
					return ErrExists
				}
			}
		}
	}
	stat, err := statAt(directory, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !private(&stat, false) {
		return ErrUnsafe
	}
	if err = unix.Unlinkat(int(directory.Fd()), name, 0); err != nil {
		return err
	}
	return directory.Sync()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var result error
	for turn := range s.turns {
		result = errors.Join(result, turn.rollback())
		if turn.directory != nil {
			result = errors.Join(result, turn.directory.Close())
			turn.directory = nil
		}
	}
	clear(s.turns)
	s.closed = true
	result = errors.Join(result, s.releaseIdle())
	return result
}

func readBounded(ctx context.Context, reader io.Reader, limit int64) ([]byte, error) {
	var data []byte
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := reader.Read(buffer)
		if int64(len(data))+int64(n) > limit {
			return nil, ErrValueTooLarge
		}
		data = append(data, buffer[:n]...)
		if errors.Is(err, io.EOF) {
			return data, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func receipt(root, namespace, name string, bytes, logical int64, digest, compression, format string) Receipt {
	mediaType := "application/json"
	if format == "jsonLines" {
		mediaType = "application/x-ndjson"
	}
	encoding := ""
	if compression == "lz4" {
		encoding = compression
	}
	return Receipt{filepath.Join(root, namespace, name), bytes, digest, logical, encoding, mediaType, "customerData"}
}
