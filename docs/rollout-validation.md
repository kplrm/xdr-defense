# Rollout Validation

This runbook is for validating that `xdr-defense` is producing content that `xdr-agent` can consume and report on.

It is intentionally shorter than the protocol contract. Use it for operator checks, not as the source of truth for payload shape.

## Preconditions

- `xdr-defense` is running in a local or test environment.
- Signing keys are configured when validating signed bundle generation.
- `xdr-agent` can reach the control-plane routes it needs.
- OpenSearch is available if rollout status and inventory visibility are part of the test.

## Validation Flow

### 1. Validate posture
- Read `GET /api/xdr-defense/policy`.
- Read `GET /api/xdr-defense/policy-overlays/{policyId}` for the target policy.
- Confirm the returned `mode`, `capabilities`, and `version` match the intended rollout state.

### 2. Validate content build

Per content family:

- YARA: build or fetch `/api/xdr-defense/yara/bundle`
- hashes: build or fetch `/api/xdr-defense/hashes/bundle`
- behavioral: build or fetch `/api/xdr-defense/behavioral/bundle`

Confirm:

- bundle generation succeeds
- signing is available when expected
- `policy_id`, `bundle_version`, and `generated_at` are present
- the bundle includes content entries and signature fields

### 3. Validate rollout trigger paths

- YARA: `POST /api/xdr-defense/yara/rollout`
- hashes: `POST /api/xdr-defense/hashes/rollout`

If the rollout request fails, check whether the cached or signed bundle was built first.

### 4. Validate agent reporting

After the agent applies or rejects content, verify the reporting surfaces:

- YARA rollout status: `GET /api/xdr-defense/yara/rollouts/status`
- hash rollout status: `GET /api/xdr-defense/hashes/rollouts/status`
- YARA inventory query: `POST /api/xdr-defense/yara-rules/inventory/query`

Confirm that:

- the agent record appears
- the reported bundle version matches expectation
- the normalized state is sensible
- partial or failed activation preserves enough detail to troubleshoot

## Expected Agent Behavior

The validation is successful when the agent:

- keeps the last verified content on failure
- reports applied, partial, or failed state explicitly
- does not treat unsigned or malformed bundles as active
- separates posture acknowledgement from content activation reporting

## Common Failure Modes

### Signing unavailable
- Bundle build returns a `503` and explains why signing is unavailable.
- Fix the signing key configuration before retrying.

### No cached bundle available
- Rollout routes may reject the request if the expected bundle has not been built yet.
- Build the bundle first, then retry rollout.

### Agent reports older or missing bundle version
- Check whether the agent is polling the canonical endpoint family.
- For older YARA agents, verify whether the legacy `/api/xdr-defense/yara-rollouts/*` alias is still required.

### Reported state stays stale
- Confirm the agent can reach the rollout status route.
- Confirm OpenSearch storage for rollout status is healthy.

## Keep This Runbook Narrow

Add new steps only when they improve operational validation. Keep schema detail in `detection-content-contract.md`.