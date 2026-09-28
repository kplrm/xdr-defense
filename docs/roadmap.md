# XDR Defense roadmap

## Current scope

- Read-only exploration of DNS, network, process and file telemetry with module-specific summaries and event details.
- Read-only search and source inspection for the Linux YARA Forge Core catalog shipped with agent releases.
- Last-reported agent protection metadata from Coordinator, with checksum verification before displaying installed rule details.
- No rule editing, external feed synchronization, signed bundle activation, policy authoring or rollout workflows.

## Follow-up work

- Package and browse multiple historical agent release catalogs while preserving exact checksum matching.
- Show initialization failures and degraded protection health after the agent/coordinator health contract supports those fields.

## Future protections

Ransomware, memory protection and behavioral rules need separate designs, runtime implementations, tests and inventory contracts before appearing as installed capabilities. XDR Sentry remains outside the active project scope.
