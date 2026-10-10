package artifact

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinalizeRevalidatesPublishedOwnership(t *testing.T) {
	for _, mutation := range []string{"contents", "file", "namespace", "lock", "permissions"} {
		t.Run(mutation, func(t *testing.T) {
			s, ns := testStore(t, DefaultLimits())
			turn := testTurn(t, s, ns)
			receipt, err := turn.Put("rows.json", 42)
			if err != nil {
				t.Fatal(err)
			}
			if err = turn.Commit(); err != nil {
				t.Fatal(err)
			}
			want := ErrMismatch
			switch mutation {
			case "contents":
				err = os.WriteFile(receipt.Path, []byte("43\n"), 0600)
			case "file":
				replacement := filepath.Join(filepath.Dir(s.root), "replacement")
				if err = os.WriteFile(replacement, []byte("42\n"), 0600); err == nil {
					err = os.Rename(replacement, receipt.Path)
				}
			case "namespace":
				path := filepath.Dir(receipt.Path)
				if err = os.Rename(path, path+"-moved"); err == nil {
					err = os.Mkdir(path, 0700)
				}
				want = ErrUnsafe
			case "lock":
				path := filepath.Join(s.root, lockName)
				if err = os.Rename(path, path+"-moved"); err == nil {
					err = os.WriteFile(path, []byte(lockContent), 0600)
				}
				want = ErrUnsafe
			case "permissions":
				err = os.Chmod(receipt.Path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = turn.Finalize(); !errors.Is(err, want) {
				t.Fatalf("accepted changed %s ownership: %v", mutation, err)
			}
		})
	}
}

func TestEmptyNamespaceCleanupPreservesReuseAndPersistentFiles(t *testing.T) {
	s, ns := testStore(t, DefaultLimits())
	turn := testTurn(t, s, ns)
	if _, err := turn.Put("canceled.json", 42); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, ns.name)
	if err := turn.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback kept an empty namespace: %v", err)
	}
	turn = testTurn(t, s, ns)
	id, err := turn.Begin("empty.jsonl", "identity", "jsonLines")
	if err != nil {
		t.Fatal(err)
	}
	if err = turn.Abort(id); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abort kept an empty namespace: %v", err)
	}
	receipt, err := turn.Put("kept.json", 43)
	if err != nil {
		t.Fatalf("namespace was not reusable: %v", err)
	}
	if err = turn.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = turn.Finalize(); err != nil {
		t.Fatal(err)
	}
	other := testTurn(t, s, ns)
	if err = other.Rollback(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(receipt.Path); err != nil || string(raw) != "43\n" {
		t.Fatalf("cleanup changed finalized contents: %q %v", raw, err)
	}
}

func TestInvalidStreamDoesNotCreateRoot(t *testing.T) {
	s, ns := testStore(t, DefaultLimits())
	turn := testTurn(t, s, ns)
	if _, err := turn.Begin("../outside.json", "identity", "jsonArray"); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid name created the artifact root: %v", err)
	}
}

func TestExistingArtifactFormatRemainsUsable(t *testing.T) {
	root := testRoot(t)
	namespace := "ctx_" + strings.Repeat("a", 64)
	if err := os.MkdirAll(filepath.Join(root, namespace), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, ".azmcp.lock")
	if err := os.WriteFile(marker, []byte("azmcp-artifacts-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(root, namespace, "existing.json")
	if err := os.WriteFile(published, []byte("42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	abandoned := filepath.Join(root, namespace, ".tmp_"+strings.Repeat("b", 64))
	if err := os.WriteFile(abandoned, []byte("unpublished\n"), 0600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.ContextFiles, limits.RootFiles = 1, 1
	s, err := NewStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := s.AllocateNamespace()
	if err != nil {
		t.Fatal(err)
	}
	turn := testTurn(t, s, ns)
	if _, err = turn.Put("next.json", 43); !errors.Is(err, ErrQuota) {
		t.Fatalf("historical artifact was not charged: %v", err)
	}
	if err = turn.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(abandoned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("historical stage was not scavenged: %v", err)
	}
	limits.RootFiles = 2
	s, err = NewStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ns, err = s.AllocateNamespace()
	if err != nil {
		t.Fatal(err)
	}
	turn = testTurn(t, s, ns)
	if _, err = turn.Put("next.json", 43); err != nil {
		t.Fatalf("existing root was unusable: %v", err)
	}
	if err = turn.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = turn.Finalize(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{marker: []byte("azmcp-artifacts-v1\n"), published: []byte("42\n")} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("historical file changed: %s %q %v", filepath.Base(path), got, err)
		}
	}
}
