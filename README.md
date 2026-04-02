# xdr-defense

`xdr-defense` is the OpenSearch Dashboards plugin that owns policy, detection content, signed bundle generation, and rollout visibility for the XDR stack.

It is the control-plane authority for what the agent should detect or prevent, but it is not the endpoint runtime.

## Scope

`xdr-defense` owns:

- global detect or prevent posture
- per-capability policy overlays
- YARA rule lifecycle and signed YARA bundles
- hash intelligence lifecycle and signed hash bundles
- behavioral rule lifecycle and signed behavioral bundles
- rollout status ingestion and operator visibility
- rollback confirmation workflows tied to prevention and recovery

It does not own:

- fleet enrollment or heartbeats
- telemetry dashboards and index lifecycle for agent event streams
- endpoint-side scanning and enforcement logic

Those concerns belong to `xdr-coordinator` and `xdr-agent`.

## Read Next

- `docs/README.md`
- `docs/detection-content-contract.md`
- `docs/rollout-validation.md`

## Current Route Families

- Policy: `/api/xdr-defense/policy*`
- YARA: `/api/xdr-defense/yara*`
- Hashes: `/api/xdr-defense/hashes*`
- Behavioral: `/api/xdr-defense/behavioral*`
- Signing: `/api/xdr-defense/signing/public-key`
- Rollback confirmation: `/api/xdr-defense/rollback/confirm`

Some legacy YARA rollout aliases still exist for compatibility with older agent behavior. The canonical route family is documented in `docs/detection-content-contract.md`.

## Design Rules

- Keep content curation centralized in the plugin.
- Ship signed artifacts to agents instead of pushing raw external feeds to endpoints.
- Keep operator contracts explicit and version-tolerant where legacy rollout aliases still exist.
- Keep the README short; treat the docs directory as the source of truth for the agent contract and rollout validation.

## Build

```bash
cd /home/kplrm/github/xdr-defense
yarn build --opensearch-dashboards-version 3.5.0
```
