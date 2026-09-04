package auth

import (
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
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

// AvailableModelsForClientAPIKeyPolicy returns a policy-scoped model list for restricted keys.
// The bool return is false when the key is unrestricted and callers should use the global list.
func (m *Manager) AvailableModelsForClientAPIKeyPolicy(clientAPIKey string, provider string, handlerType string) ([]map[string]any, bool) {
	if m == nil {
		return nil, false
	}
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.ClientAPIKeyMetadataKey: strings.TrimSpace(clientAPIKey),
	}}
	allowedGroups, restricted := m.clientAPIKeyGroupRestriction(opts)
	if !restricted {
		return nil, false
	}
	provider = strings.ToLower(strings.TrimSpace(provider))

	m.mu.RLock()
	clientIDs := make([]string, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled {
			continue
		}
		if provider != "" && strings.ToLower(strings.TrimSpace(auth.Provider)) != provider {
			continue
		}
		if auth.Attributes == nil {
			continue
		}
		authGroups := internalconfig.DecodeGroups(auth.Attributes[authGroupsAttributeKey])
		if len(authGroups) == 0 || !internalconfig.GroupsIntersect(allowedGroups, authGroups) {
			continue
		}
		clientIDs = append(clientIDs, auth.ID)
	}
	m.mu.RUnlock()

	modelRegistry := registry.GetGlobalRegistry()
	models := modelRegistry.GetAvailableModelsForClients(handlerType, clientIDs)
	if len(models) > 0 {
		return models, true
	}

	// Some built-in OAuth providers expose a shared/static model list instead of
	// registering models per auth file. In that case a restricted key should see
	// the provider's global available models when at least one auth in its groups
	// can serve the provider. Do not fall back if any selected auth has scoped
	// model registrations; an empty scoped result can then mean quota/cooldown.
	hasScopedClientModels := false
	for _, clientID := range clientIDs {
		if len(modelRegistry.GetModelsForClient(clientID)) > 0 {
			hasScopedClientModels = true
			break
		}
	}
	if !hasScopedClientModels && len(clientIDs) > 0 {
		return modelRegistry.GetAvailableModels(handlerType), true
	}

	return models, true
}

func (m *Manager) clientAPIKeyPolicyGroupsFromOptions(opts cliproxyexecutor.Options) []string {
	groups, restricted := m.clientAPIKeyGroupRestriction(opts)
	if !restricted {
		return nil
	}
	return groups
}
