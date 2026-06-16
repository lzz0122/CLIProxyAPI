package management

import (
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestParseAPIKeyListBodyStructuredPolicies(t *testing.T) {
	keys, policies, structured, err := parseAPIKeyListBody([]byte(`[
		{"key":"client-a","groups":["team-a"]},
		{"key":"client-b","groups":["team-b","team-b"]}
	]`))
	if err != nil {
		t.Fatalf("parseAPIKeyListBody() error = %v", err)
	}
	if !structured {
		t.Fatalf("expected structured=true")
	}
	if !reflect.DeepEqual(keys, []string{"client-a", "client-b"}) {
		t.Fatalf("keys = %#v", keys)
	}
	wantPolicies := []config.APIKeyPolicy{
		{Key: "client-a", Groups: []string{"team-a"}},
		{Key: "client-b", Groups: []string{"team-b"}},
	}
	if !reflect.DeepEqual(policies, wantPolicies) {
		t.Fatalf("policies = %#v", policies)
	}
}

func TestParseAPIKeyListBodyLegacyStrings(t *testing.T) {
	keys, policies, structured, err := parseAPIKeyListBody([]byte(`{"items":[" legacy ","legacy","client-a"]}`))
	if err != nil {
		t.Fatalf("parseAPIKeyListBody() error = %v", err)
	}
	if structured {
		t.Fatalf("expected structured=false")
	}
	if !reflect.DeepEqual(keys, []string{"legacy", "client-a"}) {
		t.Fatalf("keys = %#v", keys)
	}
	if len(policies) != 0 {
		t.Fatalf("policies = %#v, want empty", policies)
	}
}

func TestParseAPIKeyListBodyExplicitEmptyPolicies(t *testing.T) {
	keys, policies, structured, err := parseAPIKeyListBody([]byte(`{"api-keys":["client-a"],"api-key-policies":[]}`))
	if err != nil {
		t.Fatalf("parseAPIKeyListBody() error = %v", err)
	}
	if !structured {
		t.Fatalf("expected structured=true")
	}
	if !reflect.DeepEqual(keys, []string{"client-a"}) {
		t.Fatalf("keys = %#v", keys)
	}
	if len(policies) != 0 {
		t.Fatalf("policies = %#v, want empty", policies)
	}
}
