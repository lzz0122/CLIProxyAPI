# Plugin Host Extensions for Credential Policy

This document describes the minimal generic CPA host contract required by an
out-of-tree credential-policy plugin. The CPA repository must not contain
deployment-specific group names, downstream API keys, management UI, or NewAPI
business logic.

## Scope

The extension adds two advertised features:

- `scheduler.eligible-auth-filter.v1`
- `auth.runtime-inspection.v1`

Plugins query `host.features` during registration and must fail registration if
a required feature is absent.

## Scheduler eligibility filter

The scheduler response may contain:

```json
{
  "EligibleAuthIDs": ["credential-a", "credential-b"],
  "DelegateBuiltin": "configured",
  "Handled": true
}
```

The host validates every returned ID against the request candidates. A non-nil
empty list denies all candidates. `EligibleAuthIDs` cannot be combined with a
direct `AuthID`, and it requires the `configured` delegate.

When a plugin scheduler is active, CPA supplies all currently available
priority tiers to the plugin. After filtering, CPA applies its configured
selector to the remaining candidates. This preserves:

- priority selection after policy filtering;
- round-robin and fill-first behavior;
- configured weights;
- session affinity, including validation of an existing lower-priority binding;
- native retry and tried-credential handling.

The plugin therefore decides eligibility, not credential ordering.

## Runtime credential inspection

`host.auth.list` enumerates every credential known by the runtime manager,
including:

- file-backed OAuth credentials;
- configuration-defined Gemini, Interactions, Claude, Codex, xAI, Vertex, and
  OpenAI-compatible API-key credentials;
- supported runtime-only credentials.

Entries expose stable credential ID and auth index, source, provider, state,
priority, masked API-key account preview, and non-secret account metadata. Full
API keys are never returned.

`host.auth.get_runtime` adds safe runtime information:

- models registered for the credential;
- credential-level quota state;
- per-model lifecycle and quota state.

`host.auth.get` remains the physical JSON interface and succeeds only when a
backing credential file exists. A plugin must not use it for configuration
credentials.

## Security invariants

- API-key values must be masked before they enter a host callback response.
- Candidate IDs returned by a plugin must be validated by the host.
- A non-nil empty eligibility set must not fall back to the unfiltered selector.
- Runtime inspection must not expose access tokens, refresh tokens, cookies,
  upstream headers, proxy credentials, or raw auth metadata.
- An incompatible plugin must fail during registration rather than run with a
  partially implemented policy contract.

## Patch surface

The local extension is intentionally limited to:

- `internal/pluginhost/auth_callbacks.go`
- `internal/pluginhost/host_callbacks.go`
- `internal/pluginhost/scheduler.go`
- `sdk/cliproxy/auth/conductor_selection.go`
- `sdk/pluginabi/types.go`
- `sdk/pluginapi/types.go`

During an upstream upgrade, start from the new official tree and transplant
only the single host-extension commit. Do not merge the archived monolithic
group-management implementation.

## Upgrade verification

For every CPA upgrade:

1. format all modified Go files;
2. run pluginhost, auth, ABI, and plugin API tests;
3. build `./cmd/server`;
4. load the external plugin in an isolated candidate;
5. inspect both file-backed and configuration credentials;
6. verify a high-priority denied credential can fall through to an allowed
   lower-priority credential;
7. verify configured selector and session-affinity behavior;
8. verify no full API key appears in management responses or logs.
