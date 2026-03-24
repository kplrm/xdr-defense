# Integration Contract

## xdr-defense -> xdr-agent

`xdr-defense` is authoritative for policy and artifact bundle versions.

### Signed YARA Bundle Contract

Endpoint: `GET /api/xdr-defense/yara/bundle?policy_id=<id>`

Behavior:

- Response is a signed artifact payload for agent consumption.
- Signing is Ed25519 over canonical JSON bytes (`JSON.stringify` from a stable struct).
- Signing key source is `XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64`.
- If signing key is missing or invalid, endpoint returns HTTP `503` with actionable details and rule CRUD remains available.
- Invalid YARA rules are excluded from bundle generation so one bad custom rule does not block valid active content.

Bundle response shape:

```json
{
  "manifest_version": 1,
  "policy_id": "global-default",
  "bundle_version": 42,
  "generated_at": "2026-03-22T00:00:00Z",
  "signing_alg": "ed25519",
  "rules": [
    {
      "id": "custom-...",
      "filename": "custom-....yar",
      "content": "rule ...",
      "sha256": "...",
      "enabled": true,
      "source": "custom",
      "updatedAt": "2026-03-22T00:00:00Z"
    }
  ],
  "active_checksums": ["..."],
  "signature_base64": "...",
  "signed_payload_base64": "..."
}
```

Sync assumptions:

- Agent may be mostly offline and fetches updates on heartbeat/poll cycles.
- `xdr-defense` is authoritative for latest signed content and validation state.
- Agent should keep using last verified bundle when new bundle retrieval fails.

## xdr-defense <-> xdr-coordinator

`xdr-coordinator` should consume `xdr-defense` APIs for:

- policy CRUD
- artifact list/version status
- update job orchestration
- rollback confirmations

Suggested endpoint base: `/api/xdr-defense/*`.

YARA management endpoints:

- `GET /api/xdr-defense/yara/rules`
- `POST /api/xdr-defense/yara/rules`
- `PUT /api/xdr-defense/yara/rules/{id}`
- `DELETE /api/xdr-defense/yara/rules/{id}`
- `POST /api/xdr-defense/yara/test`
- `GET /api/xdr-defense/yara/bundle?policy_id=...`

## Correlation split

- Agent executes single-event detections.
- OpenSearch executes time-window correlations via rules in `assets/correlation-rules/`.
