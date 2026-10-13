package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func TestPutJSONPreservesCompleteValuesAndChecksums(t *testing.T) {
	values := []json.RawMessage{
		json.RawMessage(`null`),
		json.RawMessage(`9007199254740993`),
		json.RawMessage(`"<>&é🙂"`),
		json.RawMessage("  {\n  \"rows\": [1e-7, 18446744073709551615], \"flag\":true\n}\n"),
		json.RawMessage(`{"result":"` + strings.Repeat("x", 8*1024*1024-64) + `"}`),
	}
	for _, compression := range []string{"identity", "lz4"} {
		for index, value := range values {
			t.Run(compression+string(rune('0'+index)), func(t *testing.T) {
				s, ns := testStore(t, DefaultLimits())
				turn := testTurn(t, s, ns)
				name := "response.json"
				if compression == "lz4" {
					name += ".lz4"
				}
				receipt, err := turn.PutJSON(name, value, compression)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(receipt.Path); !os.IsNotExist(err) {
					t.Fatal("uncommitted export was visible", err)
				}
				if err = turn.Commit(); err != nil {
					t.Fatal(err)
				}
				if err = turn.Finalize(); err != nil {
					t.Fatal(err)
				}
				want := append(append([]byte(nil), bytes.Trim(value, " \t\r\n")...), '\n')
				got, readReceipt, err := s.Read(context.Background(), ns, name)
				if err != nil || !bytes.Equal(got, want) || receipt != readReceipt {
					t.Fatalf("export changed response bytes or receipt: got=%d want=%d receiptEqual=%v err=%v", len(got), len(want), receipt == readReceipt, err)
				}
				stored, err := os.ReadFile(receipt.Path)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(stored)
				if receipt.Bytes != int64(len(stored)) || receipt.LogicalBytes != int64(len(want)) || receipt.SHA256 != hex.EncodeToString(digest[:]) || receipt.MediaType != "application/json" {
					t.Fatal("receipt does not describe stored bytes", receipt)
				}
				if compression == "lz4" {
					if receipt.ContentEncoding != "lz4" || stored[4]&0x04 == 0 {
						t.Fatal("LZ4 export omitted its content checksum")
					}
					stored[len(stored)-1] ^= 0xff
					if err = os.WriteFile(receipt.Path, stored, 0600); err != nil {
						t.Fatal(err)
					}
					if _, _, err = s.Read(context.Background(), ns, name); err == nil {
						t.Fatal("corrupt LZ4 checksum was accepted")
					}
				}
			})
		}
	}
}

func TestPutJSONRejectsInvalidInputBeforeFilesystemAccess(t *testing.T) {
	limits := DefaultLimits()
	limits.StreamLogicalBytes = 8
	for _, test := range []struct{ name, value, compression string }{
		{"../response.json", `null`, "identity"},
		{"response.jsonl", `null`, "identity"},
		{"response.json", `null`, "lz4"},
		{"response.json.lz4", `null`, "identity"},
		{"response.json", `null`, "gzip"},
		{"response.json", `{"broken":`, "identity"},
		{"response.json", `1 2`, "identity"},
		{"response.json", string([]byte{'"', 0xff, '"'}), "identity"},
		{"response.json", `"123456"`, "identity"},
		{"response.json.lz4", `"123456"`, "lz4"},
	} {
		s, ns := testStore(t, limits)
		if _, err := testTurn(t, s, ns).PutJSON(test.name, json.RawMessage(test.value), test.compression); err == nil {
			t.Fatal("accepted invalid input", test)
		}
		if _, err := os.Stat(s.root); !os.IsNotExist(err) {
			t.Fatal("invalid input created the artifact root", test, err)
		}
	}
	s, ns := testStore(t, limits)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BeginTurn(ctx, ns); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.root); !os.IsNotExist(err) {
		t.Fatal("cancelled turn created the artifact root", err)
	}
}

func TestPutJSONFailedStoredLimitReleasesStageAndRootLock(t *testing.T) {
	limits := DefaultLimits()
	limits.StreamStoredBytes = 32
	s, ns := testStore(t, limits)
	turn := testTurn(t, s, ns)
	data := make([]byte, 4096)
	if _, err := rand.New(rand.NewSource(1)).Read(data); err != nil {
		t.Fatal(err)
	}
	value := json.RawMessage(`"` + base64.RawStdEncoding.EncodeToString(data) + `"`)
	if _, err := turn.PutJSON("response.json.lz4", value, "lz4"); !errors.Is(err, ErrValueTooLarge) {
		t.Fatal("stored limit did not reject the export", err)
	}
	if len(turn.stages) != 0 || s.lock != nil {
		t.Fatal("failed export retained staging ownership")
	}
	if _, err := turn.PutJSON("response.json.lz4", json.RawMessage(`null`), "lz4"); err != nil {
		t.Fatal("failed export kept its name reservation", err)
	}
}

func TestPutJSONCancellationRevokesStagedAndPublishedExports(t *testing.T) {
	for _, compression := range []string{"identity", "lz4"} {
		for _, published := range []bool{false, true} {
			name := compression + "/staged"
			if published {
				name = compression + "/published"
			}
			t.Run(name, func(t *testing.T) {
				s, ns := testStore(t, DefaultLimits())
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				turn, err := s.BeginTurn(ctx, ns)
				if err != nil {
					t.Fatal(err)
				}
				filename := "response.json"
				if compression == "lz4" {
					filename += ".lz4"
				}
				receipt, err := turn.PutJSON(filename, json.RawMessage(`{"complete":[1,2,3]}`), compression)
				if err != nil {
					t.Fatal(err)
				}
				if published {
					if err = turn.Commit(); err != nil {
						t.Fatal(err)
					}
				}
				cancel()
				if published {
					err = turn.Finalize()
				} else {
					err = turn.Commit()
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled export was accepted", err)
				}
				if err = turn.Rollback(); err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(receipt.Path); !os.IsNotExist(err) {
					t.Fatal("cancelled export retained published bytes", err)
				}
				if s.lock != nil || len(turn.stages) != 0 {
					t.Fatal("cancelled export retained root ownership")
				}
				if _, err = testTurn(t, s, ns).PutJSON(filename, json.RawMessage(`null`), compression); err != nil {
					t.Fatal("cancelled export kept its filename reservation", err)
				}
			})
		}
	}
}
