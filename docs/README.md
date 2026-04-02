# xdr-defense Documentation

This directory holds the defense-side docs for policy, content bundles, rollout status, and operator validation.

## Read This First

- `detection-content-contract.md`: the authoritative `xdr-defense` to `xdr-agent` contract
- `rollout-validation.md`: operator runbook for validating bundle build and rollout flows
- `sigma-integration-guide.md`: short design note for the correlation split between agent and OpenSearch

## Documentation Principles

- Keep one authoritative content contract.
- Keep operational validation separate from protocol shape.
- Prefer canonical route families and call out compatibility aliases only when they still matter.