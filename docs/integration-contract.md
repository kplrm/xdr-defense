# Integration Contract

## xdr-defense -> xdr-agent

`xdr-defense` is authoritative for policy and artifact bundle versions.

### Artifact manifest

```json
{
  "manifest_version": 1,
  "policy_version": 12,
  "activation_timestamp": "2026-03-22T00:00:00Z",
  "artifacts": [
    {
      "type": "yara",
      "version": "2026.03.22.1",
      "checksum": "sha256:...",
      "target_path": "/etc/xdr-agent/rules/malware/yara"
    }
  ]
}
```

## xdr-defense <-> xdr-manager-plugin

`xdr-manager-plugin` should consume `xdr-defense` APIs for:

- policy CRUD
- artifact list/version status
- update job orchestration
- rollback confirmations

Suggested endpoint base: `/api/xdr-defense/*`.

## Correlation split

- Agent executes single-event detections.
- OpenSearch executes time-window correlations via rules in `assets/correlation-rules/`.
