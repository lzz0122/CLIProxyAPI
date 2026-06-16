package auth

import (
	"context"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestPickNextRespectsClientAPIKeyGroups(t *testing.T) {
	selector := &trackingSelector{}
	manager := NewManager(nil, selector, nil)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			APIKeyPolicies: []internalconfig.APIKeyPolicy{
				{Key: "client-a", Groups: []string{"team-a"}},
			},
		},
	})
	manager.RegisterExecutor(schedulerTestExecutor{})
	if _, err := manager.Register(context.Background(), &Auth{
		ID:         "auth-a",
		Provider:   "test",
		Attributes: map[string]string{"groups": internalconfig.EncodeGroups([]string{"team-a"})},
	}); err != nil {
		t.Fatalf("register auth-a: %v", err)
	}
	if _, err := manager.Register(context.Background(), &Auth{
		ID:         "auth-b",
		Provider:   "test",
		Attributes: map[string]string{"groups": internalconfig.EncodeGroups([]string{"team-b"})},
	}); err != nil {
		t.Fatalf("register auth-b: %v", err)
	}

	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.ClientAPIKeyMetadataKey: "client-a",
	}}
	got, _, err := manager.pickNext(context.Background(), "test", "", opts, nil)
	if err != nil {
		t.Fatalf("pickNext() error = %v", err)
	}
	if got == nil || got.ID != "auth-a" {
		t.Fatalf("pickNext() auth = %#v, want auth-a", got)
	}
	if len(selector.lastAuthID) != 1 || selector.lastAuthID[0] != "auth-a" {
		t.Fatalf("selector candidates = %#v, want [auth-a]", selector.lastAuthID)
	}

	got, _, err = manager.pickNextLegacy(context.Background(), "test", "", cliproxyexecutor.Options{}, nil)
	if err != nil {
		t.Fatalf("unrestricted pickNext() error = %v", err)
	}
	if got == nil {
		t.Fatalf("unrestricted pickNext() auth = nil")
	}
	gotCandidates := make(map[string]struct{}, len(selector.lastAuthID))
	for _, id := range selector.lastAuthID {
		gotCandidates[id] = struct{}{}
	}
	if len(gotCandidates) != 2 {
		t.Fatalf("unrestricted selector candidates = %#v, want both auths", selector.lastAuthID)
	}
	if _, ok := gotCandidates["auth-a"]; !ok {
		t.Fatalf("unrestricted selector candidates = %#v, missing auth-a", selector.lastAuthID)
	}
	if _, ok := gotCandidates["auth-b"]; !ok {
		t.Fatalf("unrestricted selector candidates = %#v, missing auth-b", selector.lastAuthID)
	}
}

func TestPickNextRejectsUngroupedAuthForRestrictedKey(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			APIKeyPolicies: []internalconfig.APIKeyPolicy{
				{Key: "client-a", Groups: []string{"team-a"}},
			},
		},
	})
	manager.RegisterExecutor(schedulerTestExecutor{})
	if _, err := manager.Register(context.Background(), &Auth{ID: "auth-ungrouped", Provider: "test"}); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.ClientAPIKeyMetadataKey: "client-a",
	}}
	_, _, err := manager.pickNext(context.Background(), "test", "", opts, nil)
	if err == nil {
		t.Fatalf("expected pickNext() to reject ungrouped auth")
	}
}
