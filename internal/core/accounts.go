package core

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"
)

type Account struct {
	Cloud        string `json:"cloud"`
	Subscription string `json:"subscription"`
	Tenant       string `json:"tenant"`
	User         string `json:"user"`
	Name         string `json:"name"`
	State        string `json:"state"`
	UserType     string `json:"userType,omitempty"`
}
type AccountIndex struct{ Candidates []Account }

func profileFields(raw []byte, names ...string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, Fail("authentication_required", "azureProfile.json has an invalid object")
	}
	known := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		if value, ok := fields[name]; ok {
			known[name] = value
		}
	}
	return json.Marshal(known)
}

func ParseAzureProfile(raw []byte) (AccountIndex, error) {
	var index AccountIndex
	if len(raw) > 16*1024*1024 {
		return index, Fail("authentication_required", "azureProfile.json exceeds the 16 MiB limit")
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(raw) {
		return index, Fail("authentication_required", "azureProfile.json is not valid UTF-8")
	}
	if err := validateJSON(raw, nil, false); err != nil {
		return index, Fail("authentication_required", "azureProfile.json contains malformed or duplicate fields")
	}
	// Azure CLI may add fields. Only exact known spellings can contribute
	// account evidence; Go's case folding must not overwrite that evidence.
	raw, err := profileFields(raw, "subscriptions")
	if err != nil {
		return index, err
	}
	var profile struct {
		Subscriptions *[]json.RawMessage `json:"subscriptions"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil || profile.Subscriptions == nil {
		return index, Fail("authentication_required", "azureProfile.json has an invalid shape")
	}
	for _, row := range *profile.Subscriptions {
		row, err = profileFields(row, "id", "name", "state", "tenantId", "environmentName", "user")
		if err != nil {
			return index, err
		}
		var s struct {
			ID     string          `json:"id"`
			Name   string          `json:"name"`
			State  string          `json:"state"`
			Tenant string          `json:"tenantId"`
			Cloud  string          `json:"environmentName"`
			User   json.RawMessage `json:"user"`
		}
		if err = json.Unmarshal(row, &s); err != nil {
			return index, Fail("authentication_required", "azureProfile.json has an invalid subscription")
		}
		var user *struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if len(s.User) != 0 && !bytes.Equal(s.User, []byte("null")) {
			userRaw, err := profileFields(s.User, "name", "type")
			if err != nil {
				return index, err
			}
			if err = json.Unmarshal(userRaw, &user); err != nil {
				return index, Fail("authentication_required", "azureProfile.json has an invalid user")
			}
		}
		if !EqualFoldASCII(s.State, "enabled") || strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Tenant) == "" || strings.TrimSpace(s.Cloud) == "" || user == nil || strings.TrimSpace(user.Name) == "" {
			continue
		}
		pseudo := func(value string) bool {
			value = lowerASCII(strings.TrimSpace(value))
			return value == "n/a" || strings.Contains(value, "tenant level account")
		}
		if pseudo(s.ID) || pseudo(s.Name) {
			continue
		}
		index.Candidates = append(index.Candidates, Account{s.Cloud, s.ID, s.Tenant, user.Name, s.Name, s.State, user.Type})
	}
	sort.SliceStable(index.Candidates, func(i, j int) bool {
		a, b := index.Candidates[i], index.Candidates[j]
		if a.Cloud != b.Cloud {
			return a.Cloud < b.Cloud
		}
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		if a.Subscription != b.Subscription {
			return a.Subscription < b.Subscription
		}
		return a.User < b.User
	})
	return index, nil
}
func (index AccountIndex) ForCloud(cloud Cloud) []Account {
	var result []Account
	for _, account := range index.Candidates {
		if account.Cloud == string(cloud) {
			result = append(result, account)
		}
	}
	return result
}
func (index AccountIndex) Resolve(cloud Cloud) (Account, error) {
	candidates := index.ForCloud(cloud)
	switch len(candidates) {
	case 0:
		return Account{}, Fail("account_ambiguous", "no enabled subscription candidate for selected cloud")
	case 1:
		return candidates[0], nil
	default:
		return Account{}, Fail("account_ambiguous", "multiple subscription candidates for selected cloud")
	}
}
