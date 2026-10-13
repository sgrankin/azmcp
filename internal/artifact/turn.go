package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/pierrec/lz4/v4"
	"golang.org/x/sys/unix"
)

type stage struct {
	name, temp string
	id         identity
	receipt    Receipt
}
type Turn struct {
	store                            *Store
	namespace                        Namespace
	directory                        *os.File
	ctx                              context.Context
	stages                           []*stage
	committed, rolledBack, finalized bool
}

func (t *Turn) check() error {
	if t.committed || t.rolledBack || t.finalized || t.store.closed {
		return ErrClosed
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	if t.namespace.store != t.store || !validOpaque(t.namespace.name, "ctx_") {
		return ErrMismatch
	}
	return nil
}

func (t *Turn) prepare() error {
	if err := t.check(); err != nil {
		return err
	}
	if err := t.store.acquire(true); err != nil {
		return err
	}
	if t.store.namespaces[t.namespace.name] == (identity{}) {
		if err := unix.Mkdirat(int(t.store.directory.Fd()), t.namespace.name, 0700); err != nil {
			return err
		}
		stat, err := statAt(t.store.directory, t.namespace.name)
		if err != nil || !private(&stat, true) {
			return ErrUnsafe
		}
		t.store.namespaces[t.namespace.name] = fileID(&stat)
		if err := t.store.directory.Sync(); err != nil {
			return err
		}
	}
	current, err := t.store.openNamespace(t.namespace)
	if err != nil {
		return err
	}
	if t.directory == nil {
		t.directory = current
	} else {
		current.Close()
	}
	return nil
}

func (t *Turn) create(name string) (*stage, *os.File, error) {
	if _, err := statAt(t.directory, name); err == nil {
		return nil, nil, ErrExists
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, nil, ErrUnsafe
	}
	for other := range t.store.turns {
		if other.namespace != t.namespace {
			continue
		}
		for _, stage := range other.stages {
			if stage.name == name {
				return nil, nil, ErrExists
			}
		}
	}
	if err := t.store.capacity(t.namespace, 1, 0); err != nil {
		return nil, nil, err
	}
	temporary, err := randomName(".tmp_")
	if err != nil {
		return nil, nil, err
	}
	file, err := openAt(t.directory, temporary, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return nil, nil, err
	}
	stat, err := statFD(file)
	if err != nil || !private(&stat, false) {
		file.Close()
		unix.Unlinkat(int(t.directory.Fd()), temporary, 0)
		return nil, nil, ErrUnsafe
	}
	return &stage{name: name, temp: temporary, id: fileID(&stat)}, file, nil
}

// boundedWriter checks both the stored-byte ceiling and aggregate quotas before each physical write.
type boundedWriter struct {
	turn         *Turn
	file         *os.File
	limit, count int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if err := w.turn.ctx.Err(); err != nil {
		return 0, err
	}
	if w.count+int64(len(data)) > w.limit {
		return 0, ErrValueTooLarge
	}
	if err := w.turn.store.capacity(w.turn.namespace, 0, int64(len(data))); err != nil {
		return 0, err
	}
	n, err := w.file.Write(data)
	w.count += int64(n)
	return n, err
}

// PutJSON stages a complete JSON response without translating its values.
func (t *Turn) PutJSON(name string, value json.RawMessage, compression string) (result Receipt, resultErr error) {
	actualCompression, format, err := fileFormat(name)
	if err != nil || actualCompression != compression || format != "json" {
		return Receipt{}, ErrInvalidName
	}
	value = bytes.Trim(value, " \t\r\n")
	logicalBytes := int64(len(value)) + 1
	if logicalBytes > t.store.limits.StreamLogicalBytes || (compression == "identity" && logicalBytes > t.store.limits.StreamStoredBytes) {
		return Receipt{}, ErrValueTooLarge
	}
	if !utf8.Valid(value) || !json.Valid(value) {
		return Receipt{}, errors.New("artifact value is not JSON")
	}
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer func() { resultErr = errors.Join(resultErr, t.store.releaseIdle()) }()
	if err = t.prepare(); err != nil {
		return Receipt{}, err
	}
	stage, file, err := t.create(name)
	if err != nil {
		return Receipt{}, err
	}
	t.stages = append(t.stages, stage)
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			result = Receipt{}
			resultErr = errors.Join(resultErr, t.removeStage(stage))
		}
	}()
	stored := boundedWriter{t, file, t.store.limits.StreamStoredBytes, 0}
	hash := sha256.New()
	var writer io.Writer = io.MultiWriter(&stored, hash)
	var compressor *lz4.Writer
	if compression == "lz4" {
		compressor = lz4.NewWriter(writer)
		if err = compressor.Apply(lz4.BlockSizeOption(lz4.Block256Kb), lz4.ChecksumOption(true), lz4.BlockChecksumOption(false), lz4.ConcurrencyOption(1)); err != nil {
			return Receipt{}, err
		}
		writer = compressor
	}
	if _, err = writer.Write(value); err != nil {
		return Receipt{}, err
	}
	if _, err = writer.Write([]byte{'\n'}); err != nil {
		return Receipt{}, err
	}
	if compressor != nil {
		if err = compressor.Close(); err != nil {
			return Receipt{}, err
		}
	}
	if err = file.Sync(); err != nil {
		return Receipt{}, err
	}
	if err = t.ctx.Err(); err != nil {
		return Receipt{}, err
	}
	stage.receipt = receipt(t.store.root, t.namespace.name, name, stored.count, logicalBytes, hex.EncodeToString(hash.Sum(nil)), compression, "json")
	return stage.receipt, nil
}

// Discard revokes a single staged write whose audit operation failed.
func (t *Turn) Discard(receipt Receipt) error {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	if t.committed || t.rolledBack || t.store.closed {
		return ErrClosed
	}
	for _, stage := range t.stages {
		if stage.receipt == receipt {
			return t.removeStage(stage)
		}
	}
	return ErrMismatch
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func removeExact(directory *os.File, name string, id identity) error {
	stat, err := statAt(directory, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !private(&stat, false) || fileID(&stat) != id {
		return ErrMismatch
	}
	return unix.Unlinkat(int(directory.Fd()), name, 0)
}

func (t *Turn) removeStage(target *stage) error {
	err := errors.Join(removeExact(t.directory, target.temp, target.id), removeExact(t.directory, target.name, target.id))
	if err == nil {
		for index, stage := range t.stages {
			if stage == target {
				t.stages = append(t.stages[:index], t.stages[index+1:]...)
				break
			}
		}
	}
	return err
}

func (t *Turn) validateArtifact(stage *stage, name string) error {
	file, err := openAt(t.directory, name, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := statFD(file)
	if err != nil || !private(&stat, false) || fileID(&stat) != stage.id || stat.Size != stage.receipt.Bytes {
		return ErrMismatch
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, contextReader{t.ctx, file}); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != stage.receipt.SHA256 {
		return ErrMismatch
	}
	after, err := statAt(t.directory, name)
	if err != nil || fileID(&after) != stage.id || after.Size != stat.Size {
		return ErrMismatch
	}
	return nil
}

func (t *Turn) validateStage(stage *stage) error {
	if err := t.validateArtifact(stage, stage.temp); err != nil {
		return err
	}
	_, err := statAt(t.directory, stage.name)
	if err == nil {
		return ErrExists
	} else if !errors.Is(err, unix.ENOENT) {
		return ErrUnsafe
	}
	return nil
}

// Retain exact publication ownership so cancellation can undo a commit before acceptance.
func (t *Turn) Commit() (result error) {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	if t.committed {
		return t.ctx.Err()
	}
	if err := t.check(); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, t.rollback())
		}
	}()
	if len(t.stages) == 0 {
		t.committed = true
		return nil
	}
	if err := t.prepare(); err != nil {
		return err
	}
	for _, stage := range t.stages {
		if err := t.validateStage(stage); err != nil {
			return err
		}
	}
	for _, stage := range t.stages {
		if err := t.ctx.Err(); err != nil {
			return err
		}
		if err := unix.Linkat(int(t.directory.Fd()), stage.temp, int(t.directory.Fd()), stage.name, 0); err != nil {
			return err
		}
		stat, err := statAt(t.directory, stage.name)
		if err != nil || fileID(&stat) != stage.id {
			return ErrMismatch
		}
	}
	for _, stage := range t.stages {
		if err := removeExact(t.directory, stage.temp, stage.id); err != nil {
			return err
		}
	}
	if err := t.directory.Sync(); err != nil {
		return err
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	t.committed = true
	return nil
}

// Finalize relinquishes rollback ownership after the host accepts the successful turn.
func (t *Turn) Finalize() error {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	if t.finalized {
		return nil
	}
	if !t.committed || t.rolledBack || t.store.closed {
		return ErrClosed
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	if len(t.stages) != 0 {
		if err := t.store.acquire(false); err != nil {
			return err
		}
		directory, err := t.store.openNamespace(t.namespace)
		if err != nil {
			return err
		}
		directory.Close()
		for _, stage := range t.stages {
			if err := t.validateArtifact(stage, stage.name); err != nil {
				return err
			}
		}
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	t.stages = nil
	t.finalized = true
	delete(t.store.turns, t)
	var result error
	if t.directory != nil {
		result = t.directory.Close()
		t.directory = nil
	}
	return errors.Join(result, t.store.releaseIdle())
}

func (t *Turn) Rollback() error {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	return errors.Join(t.rollback(), t.store.releaseIdle())
}
func (t *Turn) rollback() error {
	if t.rolledBack {
		return nil
	}
	if t.store.closed || t.finalized {
		return ErrClosed
	}
	var result error
	owned := append([]*stage(nil), t.stages...)
	for _, stage := range owned {
		result = errors.Join(result, t.removeStage(stage))
	}
	if t.directory != nil {
		result = errors.Join(result, t.directory.Sync())
	}
	if result == nil {
		t.rolledBack = true
		delete(t.store.turns, t)
		if t.directory != nil {
			result = t.directory.Close()
			t.directory = nil
		}
	}
	return result
}
