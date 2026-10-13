package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditIsPrivateDurableBoundedAndRotates(t *testing.T) {
	root := canonicalTemp(t)
	path := filepath.Join(root, "state", "requests.jsonl")
	audit, err := NewFileAudit(path, 64*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	for i := 0; i < 15; i++ {
		if err = audit.Append(artifactAuditRecord{CorrelationID: strings.Repeat("a", 10000), Operation: "azure_export", Decision: "authorized", Bytes: 10, LogicalBytes: 10, MediaType: "application/json", Sensitivity: "customerData"}); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || info.Size() > 64*1024 {
		t.Fatal("audit not private/bounded", err, info)
	}
	for _, suffix := range []string{".1", ".2"} {
		if _, err = os.Stat(path + suffix); err != nil {
			t.Fatal("rotation missing", suffix, err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil || record["timestampUnixMs"] == nil || record["operation"] != "azure_export" {
			t.Fatal("audit envelope mismatch")
		}
	}
}
func TestAuditRejectsSymlinkWithoutWritingTarget(t *testing.T) {
	root := canonicalTemp(t)
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "audit")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	audit, err := NewFileAudit(path, 64*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	if audit.Prepare() == nil {
		t.Fatal("audit accepted a symlink")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "unchanged" {
		t.Fatal("audit changed symlink target")
	}
}
