# Detection Content Contract (Yara, Hashes, Behavioral)

## Purpose

Define the control-plane contract between `xdr-defense` and `xdr-agent` for detection content rollout where the agent ships with no prebuilt rules.

## Content Types

- `yara`
- `hashes`
- `behavioral`

## Open Source Feed Sources

- Yara: YARA Forge Core (already integrated)
- Hashes: abuse.ch MalwareBazaar hash feed (open source feed; synced into local content store)
- Behavioral: SigmaHQ behavioral rules repository (open source feed; synced into local content store)

## Unified Bundle Shape

Each content type is fetched independently using a signed bundle endpoint:

- `GET /api/xdr-defense/yara/bundle?policy_id=<id>`
- `GET /api/xdr-defense/hashes/bundle?policy_id=<id>`
- `GET /api/xdr-defense/hashes/custom-overlay/bundle?policy_id=<id>`
- `GET /api/xdr-defense/behavioral/bundle?policy_id=<id>`

Bundle payload (conceptual schema):

```json
{
  "manifest_version": 1,
  "policy_id": "global-default",
  "bundle_version": 12,
  "generated_at": "2026-03-24T10:00:00.000Z",
  "signing_alg": "ed25519",
  "rules": [
    {
      "id": "forge-core-encoded-powershell",
      "filename": "forge-core-encoded-powershell.yar",
      "content": "rule ...",
      "sha256": "...",
      "enabled": true,
      "source": "forge-core",
      "updatedAt": "2026-03-24T10:00:00.000Z"
    }
  ],
  "active_checksums": ["..."],
  "signature_base64": "...",
  "signed_payload_base64": "..."
}
```

Notes:

- `rules` remains the transport key for all content types to keep agent-side activation generic.
- For hashes, `content` is line-based hash indicators (`sha256:<hex>` or `<hex>` per line).
- For behavioral rules, `content` is YAML/JSON rule definitions sourced from Sigma.
- The custom hash overlay endpoint reuses the same signed bundle schema but only returns pending immediate custom critical SHA256 hashes, one YAML rule file per custom hash document.

## Content Management APIs

Per content type:

- `GET /api/xdr-defense/<type>/rules`
- `POST /api/xdr-defense/<type>/rules`
- `PUT /api/xdr-defense/<type>/rules/{id}`
- `DELETE /api/xdr-defense/<type>/rules/{id}`
- `POST /api/xdr-defense/<type>/bundle/build`
- `GET /api/xdr-defense/<type>/bundle?policy_id=<id>`
- `GET /api/xdr-defense/hashes/custom-overlay/bundle?policy_id=<id>`

Feed sync endpoints:

- `POST /api/xdr-defense/yara/forge-core/sync`
- `POST /api/xdr-defense/hashes/open-source/sync`
- `POST /api/xdr-defense/behavioral/open-source/sync`

## Rollout and Agent Activation

- Any create/update/enable/disable/delete operation queues rollout dispatch.
- Custom hash create/update/delete/enable/disable also updates a persisted immediate overlay set. MalwareBazaar API sync completion and daily full sync completion clear that overlay state because the next full hash bundle is authoritative.
- Agent polls bundle endpoints on interval and atomically replaces local on-disk content by type:
  - `/etc/xdr-agent/rules/malware/yara`
  - `/etc/xdr-agent/rules/malware/hashes`
  - `/etc/xdr-agent/rules/behavioral`
- Agent package does not include prebuilt yara/hash/behavioral rules.

## UI Contract

Detection tab set in `xdr-defense`:

- `Yara`
- `Hashes`
- `Behavioral Rules`
- `Bundle Status`
- `Testing`
- `Correlation UX`

Detection registry cards show:

- Total Yara Rules
- Total Behavioral Rules
- Hash Reputation Set
- Threat Intel Package
