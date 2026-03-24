# xdr-defense

OpenSearch Dashboards plugin for XDR detection/prevention management.

## Scope

- Manage global mode (`detect`/`prevent`) and per-capability policy options.
- Manage artifact lifecycle for YARA rules, behavioral rules, local IoC files, and malware hashes.
- Trigger and track agent update jobs for policy/artifact rollout.
- Host built-in OpenSearch assets:
  - index templates/mappings for alerts, prevention actions, and agent logs
  - ingest pipelines for normalization and enrichment
  - correlation content for time-window detections

## Integration model

- `xdr-agent` remains local-artifact-only and does not fetch remote threat feeds.
- `xdr-defense` fetches/curates threat intelligence and packages local artifacts.
- `xdr-coordinator` can consume `xdr-defense` APIs as source of truth for policy/artifacts.

## YARA Signed Bundle Setup

`GET /api/xdr-defense/yara/bundle` requires an Ed25519 private key in environment variable `XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64`.

Accepted key material formats after base64 decode:

- 32-byte raw Ed25519 seed
- 64-byte raw private key (first 32 bytes are used as seed)

Example key generation and export:

```bash
node -e "const { randomBytes } = require('crypto'); console.log(randomBytes(32).toString('base64'));"
export XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64='<paste-base64-seed>'
```

If this env var is missing/invalid, bundle endpoint returns HTTP `503` with details, while YARA CRUD endpoints continue working.

## YARA API Examples

```bash
# List rules
curl -s localhost:5601/api/xdr-defense/yara/rules

# Add custom rule
curl -s -X POST localhost:5601/api/xdr-defense/yara/rules \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"SuspiciousEncodedPS",
    "severity":"high",
    "tags":["powershell","custom"],
    "content":"rule suspicious_encoded_ps { strings: $a = \"-EncodedCommand\" nocase condition: $a }"
  }'

# Test rule content
curl -s -X POST localhost:5601/api/xdr-defense/yara/test \
  -H 'Content-Type: application/json' \
  -d '{"content":"rule t { condition: true }","sample_text":"powershell","lookback_minutes":60}'

# Fetch signed bundle
curl -s 'localhost:5601/api/xdr-defense/yara/bundle?policy_id=global-default'
```

## Development

```bash
npm install
npm run lint
npm run build
```
