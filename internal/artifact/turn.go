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

	"github.com/pierrec/lz4/v4"
	"golang.org/x/sys/unix"
)

type stage struct {
	name, temp string
	id         identity
	receipt    Receipt
}
type stream struct {
	stage               *stage
	file                *os.File
	writer              io.Writer
	compressor          *lz4.Writer
	compression, format string
	logical             int64
	chunks              uint16
	items               uint64
	hasValues           bool
	stored              *boundedWriter
}

type Turn struct {
	store                            *Store
	namespace                        Namespace
	directory                        *os.File
	ctx                              context.Context
	stages                           []*stage
	streams                          map[string]*stream
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

func (t *Turn) create(name, compression, format string) (*stage, *os.File, error) {
	actualCompression, actualFormat, err := fileFormat(name)
	if err != nil || actualCompression != compression || actualFormat != format {
		return nil, nil, ErrInvalidName
	}
	if _, err = statAt(t.directory, name); err == nil {
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
		for _, stream := range other.streams {
			if stream.stage.name == name {
				return nil, nil, ErrExists
			}
		}
	}
	if err = t.store.capacity(t.namespace, 1, 0); err != nil {
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

func (t *Turn) Put(name string, value any) (Receipt, error) {
	compression, format, nameErr := fileFormat(name)
	if nameErr != nil || compression != "identity" || format != "jsonArray" {
		return Receipt{}, ErrInvalidName
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return Receipt{}, err
	}
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	if err := t.check(); err != nil {
		return Receipt{}, err
	}
	if int64(buffer.Len()) > t.store.limits.ArtifactBytes {
		return Receipt{}, ErrValueTooLarge
	}
	if err := t.prepare(); err != nil {
		return Receipt{}, err
	}
	stage, file, err := t.create(name, "identity", "jsonArray")
	if err != nil {
		return Receipt{}, err
	}
	t.stages = append(t.stages, stage)
	writer := boundedWriter{t, file, t.store.limits.ArtifactBytes, 0}
	_, err = writer.Write(buffer.Bytes())
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	err = errors.Join(err, closeErr)
	if err != nil {
		return Receipt{}, errors.Join(err, t.removeStage(stage))
	}
	digest := sha256.Sum256(buffer.Bytes())
	stage.receipt = receipt(t.store.root, t.namespace.name, name, int64(buffer.Len()), int64(buffer.Len()), hex.EncodeToString(digest[:]), "identity", "jsonArray")
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

func (t *Turn) Begin(name, compression, format string) (string, error) {
	actualCompression, actualFormat, err := fileFormat(name)
	if err != nil || actualCompression != compression || actualFormat != format {
		return "", ErrInvalidName
	}
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	if err := t.prepare(); err != nil {
		return "", err
	}
	stage, file, err := t.create(name, compression, format)
	if err != nil {
		return "", err
	}
	id, err := randomName("stream_")
	if err != nil {
		file.Close()
		unix.Unlinkat(int(t.directory.Fd()), stage.temp, 0)
		return "", err
	}
	str := &stream{stage: stage, file: file, compression: compression, format: format}
	str.stored = &boundedWriter{t, file, t.store.limits.StreamStoredBytes, 0}
	str.writer = str.stored
	if compression == "lz4" {
		str.compressor = lz4.NewWriter(str.stored)
		if err = str.compressor.Apply(lz4.BlockSizeOption(lz4.Block256Kb), lz4.ChecksumOption(true), lz4.BlockChecksumOption(false), lz4.ConcurrencyOption(1)); err != nil {
			file.Close()
			unix.Unlinkat(int(t.directory.Fd()), stage.temp, 0)
			return "", err
		}
		str.writer = str.compressor
	}
	t.streams[id] = str
	if format == "jsonArray" {
		if t.store.limits.StreamLogicalBytes < 3 {
			err = ErrValueTooLarge
		} else {
			_, err = str.writer.Write([]byte("["))
			str.logical = 1
		}
		if err == nil {
			err = str.flush()
		}
		if err != nil {
			return "", errors.Join(err, t.abort(id))
		}
	}
	return id, nil
}

func (s *stream) flush() error {
	if s.compressor != nil {
		if err := s.compressor.Flush(); err != nil {
			return err
		}
	}
	return s.file.Sync()
}

func (t *Turn) CheckStreamFormat(id, format string) error {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	if err := t.check(); err != nil {
		return err
	}
	str, ok := t.streams[id]
	if !ok || str.format != format {
		return ErrMismatch
	}
	return nil
}

func (t *Turn) Append(id string, sequence uint16, values []json.RawMessage) (result error) {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	if err := t.check(); err != nil {
		return err
	}
	str, ok := t.streams[id]
	if !ok {
		return ErrMismatch
	}
	if err := t.prepare(); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, t.abort(id))
		}
	}()
	if sequence != str.chunks || sequence >= 192 || len(values) == 0 {
		return ErrMismatch
	}
	var encoded bytes.Buffer
	for index, value := range values {
		if !json.Valid(value) {
			return errors.New("artifact item is not JSON")
		}
		if str.format == "jsonArray" && (str.hasValues || index != 0) {
			encoded.WriteByte(',')
		}
		if err := json.Compact(&encoded, value); err != nil {
			return err
		}
		if str.format == "jsonLines" {
			encoded.WriteByte('\n')
		}
		if encoded.Len() > MaxAppendBytes {
			return ErrValueTooLarge
		}
	}
	suffix := int64(0)
	if str.format == "jsonArray" {
		suffix = 2
	}
	if str.logical+int64(encoded.Len())+suffix > t.store.limits.StreamLogicalBytes {
		return ErrValueTooLarge
	}
	if _, err := str.writer.Write(encoded.Bytes()); err != nil {
		return err
	}
	if err := str.flush(); err != nil {
		return err
	}
	str.logical += int64(encoded.Len())
	str.items += uint64(len(values))
	str.chunks++
	str.hasValues = true
	return nil
}

func (t *Turn) Finish(id string, chunks uint16, items uint64) (result Receipt, resultErr error) {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	if err := t.check(); err != nil {
		return Receipt{}, err
	}
	str, ok := t.streams[id]
	if !ok {
		return Receipt{}, ErrMismatch
	}
	if err := t.prepare(); err != nil {
		return Receipt{}, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, t.abort(id))
		}
	}()
	if chunks != str.chunks || items != str.items {
		return Receipt{}, ErrMismatch
	}
	suffix := []byte{}
	if str.format == "jsonArray" {
		suffix = []byte("]\n")
	}
	if str.logical+int64(len(suffix)) > t.store.limits.StreamLogicalBytes {
		return Receipt{}, ErrValueTooLarge
	}
	if _, err := str.writer.Write(suffix); err != nil {
		return Receipt{}, err
	}
	if str.compressor != nil {
		if err := str.compressor.Close(); err != nil {
			return Receipt{}, err
		}
		str.compressor = nil
	}
	if err := str.file.Sync(); err != nil {
		return Receipt{}, err
	}
	if _, err := str.file.Seek(0, io.SeekStart); err != nil {
		return Receipt{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, contextReader{t.ctx, str.file}); err != nil {
		return Receipt{}, err
	}
	if err := str.file.Close(); err != nil {
		return Receipt{}, err
	}
	str.file = nil
	str.stage.receipt = receipt(t.store.root, t.namespace.name, str.stage.name, str.stored.count, str.logical+int64(len(suffix)), hex.EncodeToString(hash.Sum(nil)), str.compression, str.format)
	t.stages = append(t.stages, str.stage)
	delete(t.streams, id)
	return str.stage.receipt, nil
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

func (t *Turn) Abort(id string) error {
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	defer t.store.releaseIdle()
	return t.abort(id)
}
func (t *Turn) abort(id string) error {
	str, ok := t.streams[id]
	if !ok {
		return nil
	}
	if str.file != nil {
		str.file.Close()
		str.file = nil
	}
	// An aborted compressor is discarded without flushing any unpublished bytes.
	str.compressor = nil
	err := removeExact(t.directory, str.stage.temp, str.stage.id)
	if err == nil {
		delete(t.streams, id)
	}
	return err
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

// Commit publishes all stages together at the host's commit point.
// The turn retains its ownership tickets so a close race can still roll them back.
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
	if len(t.streams) != 0 {
		return errors.New("unfinished artifact streams")
	}
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
	for id := range t.streams {
		result = errors.Join(result, t.abort(id))
	}
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
