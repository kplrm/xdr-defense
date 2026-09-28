# Agent release protection inventory contract

This is the authoritative contract for the rules included in XDR Agent releases and their read-only presentation in XDR Defense.

## Ownership and lifecycle

- XDR Agent collects process, file and network telemetry and enforces the Linux YARA Forge Core rules embedded in its release.
- The agent release build refreshes Forge Core, selects Linux/ELF rules, verifies compilation, and embeds the filtered source and catalog. Windows and other unsupported platform rules are excluded. Ambiguous platform rules are omitted conservatively.
- XDR Coordinator manages enrollment, agent removal/upgrades, group policies, and heartbeat inventory storage.
- XDR Defense searches and displays this inventory. It does not author, download, sign, activate, synchronize or roll out detection content.
- XDR Visualizer reads security alerts and telemetry for investigation.

Rules change through a new agent release. The old Defense policy, hash, behavioral, artifact, signing, rollback, rule-write, feed-sync and rollout APIs are removed; this is an intentional break from the legacy content-management contract. Existing stored legacy records are not migrated or deleted automatically. Ransomware, memory protection and behavioral rules are future work.

## Release catalog

The agent generator `tools/bundle_yara.py` produces `internal/detection/malware/bundle/catalog.json` alongside its Linux YARA source. Defense packages that catalog unchanged at `server/data/yara-core-linux.json`. Use `python3 scripts/prepare_catalog.py --agent-root ../xdr-agent` to refresh it from the matching agent checkout before building. The bundle workflow downloads the catalog asset from the latest published agent release.

Catalog fields:

| Field | Meaning |
| --- | --- |
| `source` | `YARA Forge Core` |
| `version` | Rule release version recorded by the agent generator |
| `platform` | `linux` |
| `rules_sha256` | SHA-256 of the filtered YARA source embedded by the agent |
| `source_sha256` | SHA-256 of the upstream Forge Core source |
| `rule_count` | Number of rules in the filtered source/catalog |
| `rules` | Rule entries with `name`, `tags`, `description`, `author`, `reference`, and complete YARA `content` |

The catalog preserves rule metadata and source attribution. It is release data, not an assertion that any endpoint has loaded those rules.

## Heartbeat inventory

Agent heartbeats optionally include `protection`:

```json
{
  "rule_source": "YARA Forge Core",
  "rule_version": "<embedded rule version>",
  "rule_count": 170,
  "mode": "enforce",
  "platform": "linux",
  "rules_sha256": "<64-character SHA-256 of the embedded Linux rules>"
}
```

The count above is illustrative; consumers use the actual report. Inventory is meaningful only after the endpoint has initialized its rule engine. Old agents can omit it and are shown as unknown. The coordinator exposes reports through authenticated `GET /api/xdr_manager/protections`:

```json
{
  "agents": [{
    "agent_id": "endpoint-id",
    "name": "hostname",
    "status": "online",
    "version": "agent-version",
    "last_seen": "2026-09-27T12:00:00.000Z",
    "protection": {}
  }],
  "total": 1
}
```

`protection` uses the full heartbeat object above or is absent. Defense displays agent status and last heartbeat; this is last reported state, not live attestation. Rule details are shown for a selected agent only when platform, rules checksum and count match the packaged catalog. If they differ, report metadata remains visible and the UI explains that details for that release are unavailable. Selecting the release catalog explicitly allows browsing independently of installed state.

## Defense HTTP endpoints

All routes use normal Dashboards authentication; no agent-facing write API remains.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /api/xdr-defense/yara/rules` | Optional query `q` (up to 500 characters), `page` (positive integer, default 1), `perPage` (1–100, default 25) | Catalog metadata, filtered `total`, `page`, `perPage`, and rule summaries without `content` |
| `GET /api/xdr-defense/yara/rules/{name}` | Exact URL-encoded rule name | Complete rule entry; 404 if absent |

Search is case-insensitive across name, description, author, reference and tags. Every whitespace-separated search term must match. An unavailable or malformed packaged catalog returns 503. Invalid request values fail validation.

## Verification and maintenance

`npm test` exercises every registered Defense endpoint using the real Dashboards validation schemas, checks searches and pagination, verifies missing-rule handling, rejects write-route registration, and tests checksum matching. `OSD_ROOT` can point tests to a separate Dashboards checkout. Tests run before local and release plugin builds.

Any endpoint or field change must update this document and the tests together. Agent/coordinator endpoint inventories remain in their respective API contracts; do not recreate content-write APIs here.
