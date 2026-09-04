package auth

import (
	"math"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type ClientAPIKeyQuotaHealthResult struct {
	Success                bool     `json:"success"`
	Authorized             bool     `json:"-"`
	QuotaAvailable         bool     `json:"quota_available"`
	Reason                 string   `json:"reason,omitempty"`
	NextAvailableAt        int64    `json:"next_available_at,omitempty"`
	RetryAfterSeconds      int64    `json:"retry_after_seconds,omitempty"`
	Groups                 []string `json:"groups,omitempty"`
	Models                 []string `json:"models,omitempty"`
	TotalCandidates        int      `json:"total_candidates"`
	AvailableCandidates    int      `json:"available_candidates"`
	QuotaBlockedCandidates int      `json:"quota_blocked_candidates"`
	OtherBlockedCandidates int      `json:"other_blocked_candidates"`
}

func (m *Manager) ClientAPIKeyQuotaHealth(clientAPIKey string, models []string) ClientAPIKeyQuotaHealthResult {
	result := ClientAPIKeyQuotaHealthResult{
		Success: true,
		Models:  normalizeQuotaHealthModels(models),
	}
	clientAPIKey = strings.TrimSpace(clientAPIKey)
	if m == nil || clientAPIKey == "" {
		result.Success = false
		result.Reason = "missing_api_key"
		return result
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if !quotaHealthAPIKeyAccepted(cfg, clientAPIKey) {
		result.Success = false
		result.Reason = "unauthorized"
		return result
	}
	result.Authorized = true
	if groups, restricted := cfg.SDKConfig.APIKeyGroupRestriction(clientAPIKey); restricted {
		result.Groups = groups
	}

	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.ClientAPIKeyMetadataKey: clientAPIKey,
	}}
	now := time.Now()
	registryRef := registry.GetGlobalRegistry()
	earliestQuotaRecover := time.Time{}

	m.mu.RLock()
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled || candidate.Status == StatusDisabled {
			continue
		}
		if !m.authAllowedByClientAPIKeyPolicy(candidate, opts) {
			continue
		}
		matchedModels := m.quotaHealthModelsForAuth(registryRef, candidate, result.Models)
		for _, modelName := range matchedModels {
			result.TotalCandidates++
			blocked, reason, _ := isAuthBlockedForModel(candidate, modelName, now)
			if !blocked {
				result.AvailableCandidates++
				continue
			}
			if reason == blockReasonCooldown {
				if next, ok := quotaHealthRecoverTime(candidate, modelName, now); ok {
					result.QuotaBlockedCandidates++
					if earliestQuotaRecover.IsZero() || next.Before(earliestQuotaRecover) {
						earliestQuotaRecover = next
					}
					continue
				}
			}
			result.OtherBlockedCandidates++
		}
	}
	m.mu.RUnlock()

	switch {
	case result.TotalCandidates == 0:
		result.QuotaAvailable = true
		result.Reason = "no_matching_auth"
	case result.AvailableCandidates > 0:
		result.QuotaAvailable = true
		result.Reason = "quota_available"
	case result.OtherBlockedCandidates > 0:
		result.QuotaAvailable = true
		result.Reason = "blocked_by_non_quota_state"
	case result.QuotaBlockedCandidates > 0:
		result.QuotaAvailable = false
		result.Reason = "quota_exhausted"
		if !earliestQuotaRecover.IsZero() {
			result.NextAvailableAt = earliestQuotaRecover.Unix()
			result.RetryAfterSeconds = int64(math.Ceil(earliestQuotaRecover.Sub(now).Seconds()))
			if result.RetryAfterSeconds < 0 {
				result.RetryAfterSeconds = 0
			}
		}
	default:
		result.QuotaAvailable = true
		result.Reason = "quota_available"
	}

	return result
}

func (m *Manager) quotaHealthModelsForAuth(registryRef *registry.ModelRegistry, auth *Auth, models []string) []string {
	if len(models) == 0 {
		return []string{""}
	}
	result := make([]string, 0, len(models))
	for _, modelName := range models {
		if m.authSupportsRouteModel(registryRef, auth, modelName) {
			result = append(result, modelName)
		}
	}
	return result
}

func normalizeQuotaHealthModels(models []string) []string {
	out := make([]string, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, modelName := range models {
		modelName = strings.TrimSpace(modelName)
		if modelName == "" {
			continue
		}
		key := canonicalModelKey(modelName)
		if key == "" {
			key = modelName
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, modelName)
	}
	return out
}

func quotaHealthAPIKeyAccepted(cfg *internalconfig.Config, key string) bool {
	if cfg == nil {
		return false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	for _, accepted := range cfg.SDKConfig.EffectiveAPIKeys() {
		if strings.TrimSpace(accepted) == key {
			return true
		}
	}
	return false
}

func quotaHealthRecoverTime(auth *Auth, modelName string, now time.Time) (time.Time, bool) {
	if auth == nil {
		return time.Time{}, false
	}
	if state := quotaHealthModelState(auth, modelName); state != nil {
		if next, ok := quotaHealthQuotaRecoverTime(state.Quota, state.NextRetryAfter, now); ok {
			return next, true
		}
	}
	return quotaHealthQuotaRecoverTime(auth.Quota, auth.NextRetryAfter, now)
}

func quotaHealthQuotaRecoverTime(quota QuotaState, retryAfter time.Time, now time.Time) (time.Time, bool) {
	if !quota.Exceeded || !strings.EqualFold(strings.TrimSpace(quota.Reason), "quota") {
		return time.Time{}, false
	}
	next := quota.NextRecoverAt
	if next.IsZero() || next.Before(now) {
		next = retryAfter
	}
	if next.IsZero() || next.Before(now) {
		return time.Time{}, false
	}
	return next, true
}

func quotaHealthModelState(auth *Auth, modelName string) *ModelState {
	if auth == nil || modelName == "" || len(auth.ModelStates) == 0 {
		return nil
	}
	if state := auth.ModelStates[modelName]; state != nil {
		return state
	}
	baseModel := canonicalModelKey(modelName)
	if baseModel != "" && baseModel != modelName {
		return auth.ModelStates[baseModel]
	}
	return nil
}
