package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "artifacts")
}
func testStore(t *testing.T, limits Limits) (*Store, Namespace) {
	t.Helper()
	s, err := NewStore(testRoot(t), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ns, err := s.AllocateNamespace()
	if err != nil {
		t.Fatal(err)
	}
	return s, ns
}
func testTurn(t *testing.T, s *Store, ns Namespace) *Turn {
	t.Helper()
	turn, err := s.BeginTurn(context.Background(), ns)
	if err != nil {
		t.Fatal(err)
	}
	return turn
}

func TestCreateOnlyPrivatePublicationAndPersistence(t *testing.T) {
	root := testRoot(t)
	s, err := NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ns, err := s.AllocateNamespace()
	if err != nil {
		t.Fatal(err)
	}
	turn := testTurn(t, s, ns)
	receipt, err := turn.Put("rows.json", map[string]any{"answer": 42})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(receipt.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged receipt path was visible: %v", err)
	}
	if err = turn.Commit(); err != nil {
		t.Fatal(err)
	}
	data, readReceipt, err := s.Read(context.Background(), ns, "rows.json")
	if err != nil || string(data) != "{\"answer\":42}\n" || readReceipt != receipt {
		t.Fatalf("read: %q %#v %v", data, readReceipt, err)
	}
	if stat, err := os.Stat(receipt.Path); err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("private file: %v %v", stat, err)
	}
	if stat, err := os.Stat(root); err != nil || stat.Mode().Perm() != 0700 {
		t.Fatalf("private root: %v %v", stat, err)
	}
	other := testTurn(t, s, ns)
	if _, err = other.Put("rows.json", 42); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	other.Rollback()
	second, err := NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondNS, _ := second.AllocateNamespace()
	secondTurn := testTurn(t, second, secondNS)
	if _, err = secondTurn.Put("rows.json", 0); !errors.Is(err, ErrInUse) {
		t.Fatalf("pending commit allowed a second writer: %v", err)
	}
	if err = turn.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := os.ReadFile(receipt.Path)
	if err != nil || !bytes.Equal(persisted, data) {
		t.Fatalf("artifact did not persist: %v", err)
	}
}

func TestRollbackCancellationAndDiscard(t *testing.T) {
	s, ns := testStore(t, DefaultLimits())
	ctx, cancel := context.WithCancel(context.Background())
	turn, err := s.BeginTurn(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := turn.Put("first.json", 42)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = turn.Commit(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = turn.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(receipt.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	turn = testTurn(t, s, ns)
	receipt, err = turn.Put("first.json", 42)
	if err != nil {
		t.Fatal(err)
	}
	if err = turn.Discard(receipt); err != nil {
		t.Fatal(err)
	}
	kept, err := turn.Put("second.json", 43)
	if err != nil {
		t.Fatal(err)
	}
	if err = turn.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(receipt.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("discarded artifact was published")
	}
	if _, err = os.Stat(kept.Path); err != nil {
		t.Fatal(err)
	}
	if err = turn.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(kept.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("post-commit rollback left publication")
	}
}

func TestQuotasIncludeStagesStreamsAndRestart(t *testing.T) {
	limits := DefaultLimits()
	limits.ArtifactBytes = 32
	limits.ContextBytes = 64
	limits.RootBytes = 64
	limits.ContextFiles = 1
	limits.RootFiles = 1
	root := testRoot(t)
	s, err := NewStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := s.AllocateNamespace()
	turn := testTurn(t, s, ns)
	if _, err = turn.Put("big.json", strings.Repeat("x", 32)); !errors.Is(err, ErrValueTooLarge) {
		t.Fatal(err)
	}
	if _, err = turn.Put("../bad.json", 42); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
	id, err := turn.Begin("stream.json", "identity", "jsonArray")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = turn.Put("second.json", 42); !errors.Is(err, ErrQuota) {
		t.Fatal(err)
	}
	if err = turn.Abort(id); err != nil {
		t.Fatal(err)
	}
	receipt, err := turn.Put("kept.json", 42)
	if err != nil {
		t.Fatal(err)
	}
	if err = turn.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = turn.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ns, _ = s.AllocateNamespace()
	turn = testTurn(t, s, ns)
	if _, err = turn.Put("other.json", 1); !errors.Is(err, ErrQuota) {
		t.Fatal("restart quota not charged", err)
	}
	if data, err := os.ReadFile(receipt.Path); err != nil || string(data) != "42\n" {
		t.Fatal(err)
	}
	turn.Rollback()
}

func TestStreamFormatsCountsCompressionAndChecksums(t *testing.T) {
	for _, compression := range []string{"identity", "lz4"} {
		for _, format := range []string{"jsonArray", "jsonLines"} {
			t.Run(compression+format, func(t *testing.T) {
				s, ns := testStore(t, DefaultLimits())
				turn := testTurn(t, s, ns)
				name := "rows.json"
				expected := "[1,{\"value\":2}]\n"
				if format == "jsonLines" {
					name = "rows.jsonl"
					expected = "1\n{\"value\":2}\n"
				}
				if compression == "lz4" {
					name += ".lz4"
				}
				id, err := turn.Begin(name, compression, format)
				if err != nil {
					t.Fatal(err)
				}
				if err = turn.Append(id, 0, []json.RawMessage{json.RawMessage(`1`), json.RawMessage(`{"value":2}`)}); err != nil {
					t.Fatal(err)
				}
				receipt, err := turn.Finish(id, 1, 2)
				if err != nil {
					t.Fatal(err)
				}
				if err = turn.Commit(); err != nil {
					t.Fatal(err)
				}
				data, actual, err := s.Read(context.Background(), ns, name)
				if err != nil || string(data) != expected || actual != receipt {
					t.Fatalf("stream read %q %#v %v", data, actual, err)
				}
				if err = turn.Finalize(); err != nil {
					t.Fatal(err)
				}
				if compression == "lz4" {
					stored, err := os.ReadFile(receipt.Path)
					if err != nil {
						t.Fatal(err)
					}
					stored[len(stored)-1] ^= 0xff
					if err = os.WriteFile(receipt.Path, stored, 0600); err != nil {
						t.Fatal(err)
					}
					if _, _, err = s.Read(context.Background(), ns, name); err == nil {
						t.Fatal("corrupt content checksum accepted")
					}
				}
			})
		}
	}
}

func TestFailedStreamReleasesItsReservation(t *testing.T) {
	limits := DefaultLimits()
	limits.StreamLogicalBytes = 8
	s, ns := testStore(t, limits)
	turn := testTurn(t, s, ns)
	id, err := turn.Begin("rows.json", "identity", "jsonArray")
	if err != nil {
		t.Fatal(err)
	}
	if err = turn.Append(id, 0, []json.RawMessage{json.RawMessage(`"0123456789"`)}); !errors.Is(err, ErrValueTooLarge) {
		t.Fatal(err)
	}
	if _, err = turn.Put("rows.json", 42); err != nil {
		t.Fatalf("failed stream kept reservation: %v", err)
	}
	if err = turn.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinksNamespaceReplacementAndExactRollback(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		root := testRoot(t)
		outside := filepath.Dir(root)
		if err := os.Symlink(outside, root); err != nil {
			t.Fatal(err)
		}
		s, err := NewStore(root, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		ns, _ := s.AllocateNamespace()
		if _, err := testTurn(t, s, ns).Put("rows.json", 42); !errors.Is(err, ErrUnsafe) {
			t.Fatal(err)
		}
	})
	t.Run("file", func(t *testing.T) {
		s, ns := testStore(t, DefaultLimits())
		initial := testTurn(t, s, ns)
		if _, err := initial.Put("initial.json", 0); err != nil {
			t.Fatal(err)
		}
		if err := initial.Rollback(); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(s.root, ns.name), 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(s.root), "outside")
		if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(s.root, ns.name, "rows.json")); err != nil {
			t.Fatal(err)
		}
		turn := testTurn(t, s, ns)
		if _, err := turn.Put("rows.json", 42); err == nil {
			t.Fatal("followed destination symlink")
		}
		data, _ := os.ReadFile(target)
		if string(data) != "keep" {
			t.Fatal("changed outside file")
		}
		turn.Rollback()
	})
	t.Run("namespace", func(t *testing.T) {
		s, ns := testStore(t, DefaultLimits())
		turn := testTurn(t, s, ns)
		if _, err := turn.Put("initial.json", 0); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(s.root, ns.name)
		if err := os.Rename(directory, directory+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := turn.Put("rows.json", 42); !errors.Is(err, ErrUnsafe) {
			t.Fatal(err)
		}
		turn.Rollback()
	})
	t.Run("replacement", func(t *testing.T) {
		s, ns := testStore(t, DefaultLimits())
		turn := testTurn(t, s, ns)
		receipt, err := turn.Put("rows.json", 42)
		if err != nil {
			t.Fatal(err)
		}
		if err = turn.Commit(); err != nil {
			t.Fatal(err)
		}
		replacement := receipt.Path + ".replacement"
		if err = os.WriteFile(replacement, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(replacement, receipt.Path); err != nil {
			t.Fatal(err)
		}
		if err = turn.Rollback(); !errors.Is(err, ErrMismatch) {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(receipt.Path)
		if string(data) != "keep" {
			t.Fatal("deleted unrelated replacement")
		}
	})
}

func TestConcurrentCreateOnlyNameReservation(t *testing.T) {
	s, ns := testStore(t, DefaultLimits())
	var workers sync.WaitGroup
	results := make(chan *Turn, 16)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			turn, err := s.BeginTurn(context.Background(), ns)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err = turn.Put("same.json", 42); err == nil {
				results <- turn
			} else if errors.Is(err, ErrExists) {
				turn.Rollback()
			} else {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	close(results)
	var winners []*Turn
	for turn := range results {
		winners = append(winners, turn)
	}
	if len(winners) != 1 {
		t.Fatalf("create winners=%d", len(winners))
	}
	if err := winners[0].Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseRollsBackActiveAndScavengesAbandonedStages(t *testing.T) {
	root := testRoot(t)
	s, err := NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := s.AllocateNamespace()
	turn := testTurn(t, s, ns)
	receipt, err := turn.Put("rows.json", 42)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(receipt.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("close published active turn")
	}
	temporary, _ := randomName(".tmp_")
	if err = os.Mkdir(filepath.Join(root, ns.name), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ns.name, temporary)
	if err = os.WriteFile(path, []byte("abandoned"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	newNS, _ := s.AllocateNamespace()
	newTurn := testTurn(t, s, newNS)
	if _, err = newTurn.Put("new.json", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restart retained abandoned stage")
	}
}

func TestLazySharedRootLocksOnlyOwnedWrites(t *testing.T) {
	root := testRoot(t)
	first, err := NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewStore(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	firstNS, _ := first.AllocateNamespace()
	secondNS, _ := second.AllocateNamespace()
	firstTurn := testTurn(t, first, firstNS)
	secondTurn := testTurn(t, second, secondNS)
	if _, err = os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("idle construction touched the artifact root", err)
	}
	if err = firstTurn.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = firstTurn.Finalize(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a turn without writes touched the artifact root", err)
	}
	firstTurn = testTurn(t, first, firstNS)
	if _, err = firstTurn.Put("first.json", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = secondTurn.Put("second.json", 2); !errors.Is(err, ErrInUse) {
		t.Fatal("staged ownership did not hold the root lock", err)
	}
	if err = firstTurn.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = secondTurn.Put("second.json", 2); !errors.Is(err, ErrInUse) {
		t.Fatal("unfinalized publication did not hold rollback ownership", err)
	}
	if err = firstTurn.Finalize(); err != nil {
		t.Fatal(err)
	}
	if _, err = secondTurn.Put("second.json", 2); err != nil {
		t.Fatal("idle first store blocked the second write", err)
	}
	if err = secondTurn.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = secondTurn.Finalize(); err != nil {
		t.Fatal(err)
	}
	thirdTurn := testTurn(t, first, firstNS)
	streamID, err := thirdTurn.Begin("rows.jsonl", "identity", "jsonLines")
	if err != nil {
		t.Fatal(err)
	}
	fourthTurn := testTurn(t, second, secondNS)
	if _, err = fourthTurn.Put("fourth.json", 4); !errors.Is(err, ErrInUse) {
		t.Fatal("empty stream did not retain the root lock", err)
	}
	if err = thirdTurn.Abort(streamID); err != nil {
		t.Fatal(err)
	}
	if _, err = fourthTurn.Put("fourth.json", 4); err != nil {
		t.Fatal("last stream abort did not release the root lock", err)
	}
	if err = fourthTurn.Rollback(); err != nil {
		t.Fatal(err)
	}
	receipt, err := thirdTurn.Put("discarded.json", 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = thirdTurn.Discard(receipt); err != nil {
		t.Fatal(err)
	}
	fifthTurn := testTurn(t, second, secondNS)
	if _, err = fifthTurn.Put("fifth.json", 5); err != nil {
		t.Fatal("last stage discard did not release the root lock", err)
	}
}
