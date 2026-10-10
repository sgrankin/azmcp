package core

import (
	"bytes"
	"encoding/json"
	"testing"

	reviewed "azmcp/fixtures"
)

func TestProfileUnknownCaseAliasesDoNotHideAmbiguity(t *testing.T) {
	row := `{"id":"` + sub + `","name":"first","state":"Enabled","tenantId":"` + tenant + `","environmentName":"AzureCloud","user":{"name":"synthetic"}}`
	raw := []byte(`{"subscriptions":[` + row + `,` + row + `],"SUBSCRIPTIONS":[` + row + `]}`)
	index, err := ParseAzureProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Candidates) != 2 {
		t.Fatalf("unknown field concealed canonical account evidence: %d", len(index.Candidates))
	}
	_, err = index.Resolve(Commercial)
	errorCode(t, err, "account_ambiguous")
}

func TestManifestDefaultQueryListRetainsRustHash(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(reviewed.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	delete(m["routes"].([]any)[0].(map[string]any), "allowedQueryParameters")
	raw := mustJSON(t, m)
	if _, err := ParseManifest(raw); err != nil {
		t.Fatalf("omitted default changed the reviewed policy identity: %v", err)
	}
	raw = bytes.Replace(reviewed.Manifest, []byte(`"allowedQueryParameters": []`), []byte(`"allowedQueryParameters": null`), 1)
	_, err := ParseManifest(raw)
	errorCode(t, err, "invalid_request")
}

func TestCanonicalJSONUsesRustUnicodeAndNumberSpelling(t *testing.T) {
	for _, input := range []struct{ number, want string }{{"1e0", "1.0"}, {"-0", "-0.0"}, {"1e-6", "1e-6"}, {"100000000000000000000", "1e+20"}} {
		raw, err := encodeCanonical(map[string]any{"n": json.Number(input.number), "s": "\u2028\u2029\\u2028"}, false)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"n":` + input.want + `,"s":"` + "\u2028\u2029" + `\\u2028"}`
		if string(raw) != want {
			t.Fatalf("canonical JSON for %s: %s, want %s", input.number, raw, want)
		}
	}
}

func TestClosedJSONRejectsUnpairedUnicodeSurrogates(t *testing.T) {
	for _, input := range []string{`["\ud800"]`, `["\udfff"]`, `["\ud800\ud800"]`} {
		var values []string
		errorCode(t, DecodeClosed([]byte(input), &values), "invalid_request")
	}
	var values []string
	if err := DecodeClosed([]byte(`["\ud83d\ude00","\\ud800"]`), &values); err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0] != "😀" || values[1] != `\ud800` {
		t.Fatalf("valid Unicode changed: %#v", values)
	}
}

func TestTargetQueryInvalidUTF8PreservesRustReplacementBoundaries(t *testing.T) {
	for _, input := range []struct{ raw, want string }{
		{"%FF%FF", "%EF%BF%BD%EF%BF%BD"},
		{"%E1%80x", "%EF%BF%BDx"},
		{"%ED%A0%80", "%EF%BF%BD%EF%BF%BD%EF%BF%BD"},
		{"%F0%90%80x", "%EF%BF%BDx"},
	} {
		target, err := ParseTarget("/a?name=" + input.raw)
		if err != nil {
			t.Fatal(err)
		}
		if want := "/a?name=" + input.want; target.String() != want {
			t.Fatalf("query %s: %s, want %s", input.raw, target.String(), want)
		}
	}
}
