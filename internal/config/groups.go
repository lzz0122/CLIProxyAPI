package config

import (
	"encoding/json"
	"strings"
)

const authGroupsWildcard = "*"

// NormalizeAPIKeys trims, drops empty values, and preserves first-seen order.
func NormalizeAPIKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeGroups trims, drops empty values, and deduplicates names case-insensitively.
func NormalizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" {
			continue
		}
		key := normalizeGroupMatchKey(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// GroupsAllowAll reports whether groups contains the wildcard group.
func GroupsAllowAll(groups []string) bool {
	for _, group := range groups {
		if strings.TrimSpace(group) == authGroupsWildcard {
			return true
		}
	}
	return false
}

// GroupsIntersect reports whether two group lists share at least one name.
func GroupsIntersect(left, right []string) bool {
	left = NormalizeGroups(left)
	right = NormalizeGroups(right)
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	if GroupsAllowAll(left) || GroupsAllowAll(right) {
		return true
	}
	seen := make(map[string]struct{}, len(left))
	for _, group := range left {
		seen[normalizeGroupMatchKey(group)] = struct{}{}
	}
	for _, group := range right {
		if _, ok := seen[normalizeGroupMatchKey(group)]; ok {
			return true
		}
	}
	return false
}

// EncodeGroups serializes auth groups into an Auth attribute value.
func EncodeGroups(groups []string) string {
	groups = NormalizeGroups(groups)
	if len(groups) == 0 {
		return ""
	}
	data, err := json.Marshal(groups)
	if err != nil {
		return ""
	}
	return string(data)
}

// DecodeGroups parses an Auth attribute value. It accepts JSON arrays and a
// legacy comma-delimited fallback for hand-written attributes.
func DecodeGroups(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var groups []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &groups); err == nil {
			return NormalizeGroups(groups)
		}
	}
	return NormalizeGroups(strings.Split(raw, ","))
}

// NormalizeAPIKeyPolicies trims and deduplicates policy entries by key.
func NormalizeAPIKeyPolicies(policies []APIKeyPolicy) []APIKeyPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := make([]APIKeyPolicy, 0, len(policies))
	indexByKey := make(map[string]int, len(policies))
	for _, policy := range policies {
		key := strings.TrimSpace(policy.Key)
		if key == "" {
			continue
		}
		groups := NormalizeGroups(policy.Groups)
		if idx, ok := indexByKey[key]; ok {
			merged := append(append([]string(nil), out[idx].Groups...), groups...)
			out[idx].Groups = NormalizeGroups(merged)
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, APIKeyPolicy{Key: key, Groups: groups})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SanitizeAPIKeyPolicies normalizes legacy keys and structured key policies.
func (cfg *SDKConfig) SanitizeAPIKeyPolicies() {
	if cfg == nil {
		return
	}
	cfg.APIKeys = NormalizeAPIKeys(cfg.APIKeys)
	cfg.APIKeyPolicies = NormalizeAPIKeyPolicies(cfg.APIKeyPolicies)
}

// EffectiveAPIKeys returns all client API keys accepted by config-based auth.
func (cfg *SDKConfig) EffectiveAPIKeys() []string {
	if cfg == nil {
		return nil
	}
	keys := append([]string(nil), cfg.APIKeys...)
	for _, policy := range cfg.APIKeyPolicies {
		keys = append(keys, policy.Key)
	}
	return NormalizeAPIKeys(keys)
}

// APIKeyGroupRestriction returns the group restriction for a client API key.
// The second return value is false when the key is unrestricted.
func (cfg *SDKConfig) APIKeyGroupRestriction(key string) ([]string, bool) {
	if cfg == nil {
		return nil, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}
	var groups []string
	found := false
	for _, policy := range cfg.APIKeyPolicies {
		if strings.TrimSpace(policy.Key) != key {
			continue
		}
		found = true
		groups = append(groups, policy.Groups...)
	}
	groups = NormalizeGroups(groups)
	if !found || len(groups) == 0 || GroupsAllowAll(groups) {
		return nil, false
	}
	return groups, true
}

func normalizeGroupMatchKey(group string) string {
	return strings.ToLower(strings.TrimSpace(group))
}
