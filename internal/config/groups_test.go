package config

import (
	"reflect"
	"testing"
)

func TestAPIKeyGroupRestriction(t *testing.T) {
	cfg := &SDKConfig{
		APIKeys: []string{" legacy ", "client-a"},
		APIKeyPolicies: []APIKeyPolicy{
			{Key: " client-a ", Groups: []string{" Team-A ", "team-a", "team-b"}},
			{Key: "client-all", Groups: []string{"*"}},
			{Key: "client-open"},
		},
	}
	cfg.SanitizeAPIKeyPolicies()

	if got := cfg.EffectiveAPIKeys(); !reflect.DeepEqual(got, []string{"legacy", "client-a", "client-all", "client-open"}) {
		t.Fatalf("EffectiveAPIKeys() = %#v", got)
	}

	groups, restricted := cfg.APIKeyGroupRestriction("client-a")
	if !restricted {
		t.Fatalf("expected client-a to be restricted")
	}
	if !reflect.DeepEqual(groups, []string{"Team-A", "team-b"}) {
		t.Fatalf("client-a groups = %#v", groups)
	}

	if _, restricted := cfg.APIKeyGroupRestriction("legacy"); restricted {
		t.Fatalf("expected legacy key to be unrestricted")
	}
	if _, restricted := cfg.APIKeyGroupRestriction("client-all"); restricted {
		t.Fatalf("expected wildcard key to be unrestricted")
	}
	if _, restricted := cfg.APIKeyGroupRestriction("client-open"); restricted {
		t.Fatalf("expected empty policy groups to be unrestricted")
	}
}

func TestEncodeDecodeGroups(t *testing.T) {
	encoded := EncodeGroups([]string{" Team A ", "team a", "Team B"})
	if encoded == "" {
		t.Fatalf("EncodeGroups() returned empty")
	}
	if got := DecodeGroups(encoded); !reflect.DeepEqual(got, []string{"Team A", "Team B"}) {
		t.Fatalf("DecodeGroups(json) = %#v", got)
	}
	if got := DecodeGroups("Team A, Team B,team a"); !reflect.DeepEqual(got, []string{"Team A", "Team B"}) {
		t.Fatalf("DecodeGroups(csv) = %#v", got)
	}
	if !GroupsIntersect([]string{"team-a"}, []string{"Team-A"}) {
		t.Fatalf("expected case-insensitive group intersection")
	}
}
