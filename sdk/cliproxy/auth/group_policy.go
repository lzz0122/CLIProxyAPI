package auth

import (
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const authGroupsAttributeKey = "groups"

func clientAPIKeyFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	value, ok := meta[cliproxyexecutor.ClientAPIKeyMetadataKey]
	if !ok {
		return ""
	}
	if key, ok := value.(string); ok {
		return strings.TrimSpace(key)
	}
	return ""
}

func (m *Manager) clientAPIKeyGroupRestriction(opts cliproxyexecutor.Options) ([]string, bool) {
	if m == nil {
		return nil, false
	}
	key := clientAPIKeyFromMetadata(opts.Metadata)
	if key == "" {
		return nil, false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return nil, false
	}
	return cfg.SDKConfig.APIKeyGroupRestriction(key)
}

func (m *Manager) clientAPIKeyGroupSelectionRequired(opts cliproxyexecutor.Options) bool {
	_, restricted := m.clientAPIKeyGroupRestriction(opts)
	return restricted
}

func (m *Manager) authAllowedByClientAPIKeyPolicy(auth *Auth, opts cliproxyexecutor.Options) bool {
	allowedGroups, restricted := m.clientAPIKeyGroupRestriction(opts)
	if !restricted {
		return true
	}
	if auth == nil || auth.Attributes == nil {
		return false
	}
	authGroups := internalconfig.DecodeGroups(auth.Attributes[authGroupsAttributeKey])
	if len(authGroups) == 0 {
		return false
	}
	return internalconfig.GroupsIntersect(allowedGroups, authGroups)
}
