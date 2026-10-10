package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	reviewed "azmcp/fixtures"
)

func TestCheckRejectsStaleBytesWithoutRewriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	stale := append(append([]byte{}, reviewed.Manifest...), ' ')
	if err := os.WriteFile(path, stale, 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--check", "--manifest", path}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("unexpected check: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, stale) {
		t.Fatal("check changed the input")
	}
}
func TestImportUsesSeparateSeedAndChecksGeneratedOutput(t *testing.T) {
	dir := t.TempDir()
	seed, manifest, catalog, review := filepath.Join(dir, "seed.json"), filepath.Join(dir, "manifest.json"), filepath.Join(dir, "catalog.json"), filepath.Join(dir, "review.json")
	rawCatalog, err := reviewed.Files.ReadFile("upstream/azure-rest-storage-2023-05-01.json")
	if err != nil {
		t.Fatal(err)
	}
	rawReview, err := reviewed.Files.ReadFile("upstream/azure-rest-storage-review-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{seed: reviewed.SeedManifest, catalog: rawCatalog, review: rawReview} {
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--write", "--manifest", manifest, "--seed", seed, "--upstream", catalog, "--review", review}
	if err = run(args, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(manifest)
	if !bytes.Equal(got, reviewed.Manifest) {
		t.Fatal("CLI import differs from runtime fixture")
	}
	args[0] = "--check"
	if err = run(args, io.Discard); err != nil {
		t.Fatal(err)
	}
	stale := append(got, ' ')
	if err = os.WriteFile(manifest, stale, 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(args, io.Discard); err == nil {
		t.Fatal("stale generated output was accepted")
	}
	after, _ := os.ReadFile(manifest)
	if !bytes.Equal(after, stale) {
		t.Fatal("check rewrote stale generated output")
	}
	args[2] = seed
	if err = run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "different files") {
		t.Fatalf("aliased seed/output accepted: %v", err)
	}
	if err = run([]string{"--upstream", catalog, "--review", review}, io.Discard); err == nil || !strings.Contains(err.Error(), "--seed") {
		t.Fatalf("incomplete import accepted: %v", err)
	}
}

func TestImportCannotOverwriteSeedThroughFileAlias(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			seed, output := filepath.Join(dir, "seed.json"), filepath.Join(dir, "output.json")
			if err := os.WriteFile(seed, reviewed.SeedManifest, 0600); err != nil {
				t.Fatal(err)
			}
			link := os.Symlink
			if kind == "hardlink" {
				link = os.Link
			}
			if err := link(seed, output); err != nil {
				t.Fatal(err)
			}
			catalog, review := filepath.Join(dir, "catalog.json"), filepath.Join(dir, "review.json")
			for path, source := range map[string]string{catalog: "upstream/azure-rest-storage-2023-05-01.json", review: "upstream/azure-rest-storage-review-v1.json"} {
				raw, err := reviewed.Files.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := run([]string{"--write", "--manifest", output, "--seed", seed, "--upstream", catalog, "--review", review}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "different files") {
				t.Fatalf("seed alias was accepted: %v", err)
			}
			raw, err := os.ReadFile(seed)
			if err != nil || !bytes.Equal(raw, reviewed.SeedManifest) {
				t.Fatalf("seed was overwritten: %v", err)
			}
		})
	}
}
