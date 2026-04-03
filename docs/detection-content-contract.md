# Detection Content Contract

This document is the authoritative `xdr-defense` to `xdr-agent` contract for policy overlays, signed content bundles, and rollout state reporting.

## Ownership

`xdr-defense` owns:

- global posture mode
- capability-level policy overlays
- content curation and signing
- rollout status storage and operator visibility

`xdr-agent` owns:

- local verification and activation of signed content
- endpoint-side scanning and enforcement
- reporting activation and health state back to the control plane

`xdr-coordinator` may surface rollout commands to agents, but it does not become the source of truth for content state.

## Policy Contract

### Canonical routes
- `GET /api/xdr-defense/policy`
- `PUT /api/xdr-defense/policy`
- `GET /api/xdr-defense/policy-overlays/{policyId}`
- `POST /api/xdr-defense/policy-rollouts/ack`

### Overlay response shape

The overlay returned to the agent is centered on:

- `manager_policy_id`
- `mode`
- `capabilities`
- `updatedAt`
- `version`

Semantics:

- `mode` is `detect` or `prevent`.
- `capabilities` controls per-feature behavior such as YARA, hashes, behavioral logic, ransomware shield, rollback, and memory-focused paths.
- `version` is the posture version the agent should acknowledge when applied.

## Content Types

The plugin currently manages three content families:

- YARA
- hashes
- behavioral rules

The agent ships without assuming prebuilt runtime content. It should consume what the control plane signs and exposes.

## Canonical Content Routes

### YARA
- `GET /api/xdr-defense/yara/rules`
- `POST /api/xdr-defense/yara/rules`
- `PUT /api/xdr-defense/yara/rules/{id}`
- `DELETE /api/xdr-defense/yara/rules/{id}`
- `POST /api/xdr-defense/yara/test`
- `GET /api/xdr-defense/yara/bundle?policy_id=<id>`
- `POST /api/xdr-defense/yara/bundle/build`
- `POST /api/xdr-defense/yara/forge-core/sync`
- `GET /api/xdr-defense/yara/rollouts/status`
- `POST /api/xdr-defense/yara/rollouts/status`
- `POST /api/xdr-defense/yara/rollouts/retry`
- `POST /api/xdr-defense/yara/rollouts/ack`
- `POST /api/xdr-defense/yara/rollout`

Compatibility note:

- The legacy aliases under `/api/xdr-defense/yara-rollouts/*` still exist and should remain supported while older agent behavior may still call them.

### Hashes
- `GET /api/xdr-defense/hashes/rules`
- `POST /api/xdr-defense/hashes/rules`
- `PUT /api/xdr-defense/hashes/rules/{id}`
- `DELETE /api/xdr-defense/hashes/rules/{id}`
- `GET /api/xdr-defense/hashes/bundle?policy_id=<id>`
- `POST /api/xdr-defense/hashes/bundle/build`
- `GET /api/xdr-defense/hashes/custom-overlay/bundle?policy_id=<id>`
- `GET /api/xdr-defense/hashes/rollouts/status`
- `POST /api/xdr-defense/hashes/rollouts/status/report`
- `POST /api/xdr-defense/hashes/rollouts/retry`
- `POST /api/xdr-defense/hashes/rollout`
- `POST /api/xdr-defense/hashes/malwarebazaar/sync`
- `POST /api/xdr-defense/hashes/malwarebazaar/full/sync`
- `POST /api/xdr-defense/hashes/open-source/sync`

### Behavioral
- `GET /api/xdr-defense/behavioral/rules`
- `POST /api/xdr-defense/behavioral/rules`
- `PUT /api/xdr-defense/behavioral/rules/{id}`
- `DELETE /api/xdr-defense/behavioral/rules/{id}`
- `GET /api/xdr-defense/behavioral/bundle?policy_id=<id>`
- `POST /api/xdr-defense/behavioral/bundle/build`
- `POST /api/xdr-defense/behavioral/open-source/sync`

## Signed Bundle Shape

The content families use the same operational model even when their internal payloads differ.

Common fields:

```json
{
  "manifest_version": 1,
  "policy_id": "global-default",
  "bundle_version": 12,
  "generated_at": "2026-03-24T10:00:00.000Z",
  "signing_alg": "ed25519",
  "rules": [
    {
      "id": "example-rule",
      "filename": "example-rule.yar",
      "content": "rule ...",
      "sha256": "...",
      "enabled": true,
      "source": "custom",
      "updatedAt": "2026-03-24T10:00:00.000Z"
    }
  ],
  "active_checksums": ["..."],
  "signature_base64": "...",
  "signed_payload_base64": "..."
}
```

Rules for interpretation:

- `rules` remains the transport key across content types so the agent can apply a generic activation path.
- Hash bundles use line-oriented indicator content rather than YARA text.
- Hash bundle YAML entries are keyed by `sha256` and may include optional context fields used by agent alerts: `name`, `severity`, `source`, `family`, `mime_type`, and `first_seen_utc`.
- Behavioral bundles use structured rule content produced from the behavioral store.
- The hash custom overlay bundle is separate from the full hash bundle and exists for immediate critical custom entries.

## Agent Expectations

The agent should:

- verify signatures before activation
- keep the previously verified bundle active if the new one is invalid
- apply content atomically per content type
- report rollout status after activation attempts
- acknowledge posture versions after policy application

The agent should not:

- fetch external feeds directly from each host
- treat unsigned content as authoritative
- assume every content family is bundled into one endpoint

## Rollout Status Semantics

### YARA
YARA rollout status records center on:

- `agent_id`
- `policy_id`
- `state`
- `bundle_version`
- `total_rules`
- `loaded_rules`
- `failed_rules`
- `reported_at`

Normalized states include:

- `applied`
- `partial`
- `failed`
- `pending`
- `offline/unknown`

### Hashes
Hash rollout status records center on:

- `agent_id`
- `policy_id`
- `state`
- `full_bundle_version`
- `custom_bundle_version`
- `reported_at`
- `error`

### Rule inventory
YARA inventory ingestion is separate from rollout status and is used for operator visibility into loaded and failed rules.

## Correlation Split

- The agent performs single-event detection and enforcement.
- OpenSearch performs time-window and cross-event correlation.
- `xdr-defense` may curate behavioral content, but correlation across historical event windows should remain a backend concern.

## Documentation Rule

If new content endpoints or rollout fields are introduced, update this file first and remove or replace any overlapping documentation elsewhere.
