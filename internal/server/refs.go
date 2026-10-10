package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var errReference = errors.New("reference is invalid, expired, or unavailable in this context")

type storedRef struct {
	id      string
	value   json.RawMessage
	expires time.Time
}
type refStore struct {
	entries []storedRef
	bytes   int
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *refStore) sweep(now time.Time) {
	out := s.entries[:0]
	for _, e := range s.entries {
		if now.Before(e.expires) {
			out = append(out, e)
		} else {
			s.bytes -= len(e.value)
		}
	}
	// Release expired values retained by the backing array.
	clear(s.entries[len(out):])
	s.entries = out
}

func (s *refStore) put(value json.RawMessage, now time.Time) (string, error) {
	if !json.Valid(value) || len(value) > 480*1024 {
		return "", errReference
	}
	s.sweep(now)
	for len(s.entries) >= 32 || s.bytes+len(value) > 4*1024*1024 {
		s.bytes -= len(s.entries[0].value)
		s.entries[0] = storedRef{}
		s.entries = s.entries[1:]
	}
	token, err := randomHex(32)
	if err != nil {
		return "", errReference
	}
	token = "ref_" + token
	s.entries = append(s.entries, storedRef{token, append(json.RawMessage(nil), value...), now.Add(5 * time.Minute)})
	s.bytes += len(value)
	return token, nil
}

func (s *refStore) get(token string, now time.Time) (json.RawMessage, error) {
	if len(token) != 68 || !strings.HasPrefix(token, "ref_") {
		return nil, errReference
	}
	if _, err := hex.DecodeString(token[4:]); err != nil || token != strings.ToLower(token) {
		return nil, errReference
	}
	s.sweep(now)
	for _, e := range s.entries {
		if e.id == token {
			return append(json.RawMessage(nil), e.value...), nil
		}
	}
	return nil, errReference
}
