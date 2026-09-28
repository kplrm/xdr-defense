# Telemetry explorer

XDR Defense reads endpoint telemetry from `.xdr-agent-telemetry-*` through the current Dashboards user's OpenSearch permissions. The DNS, Network, Process and File tabs use the stable envelope fields `@timestamp`, `event.module`, `event.type`, `host.hostname`, and `agent.id`. Payload columns reflect the current agent output; absent fields display as an em dash.

The File tab selects `event.module=telemetry.file`. File access and integrity changes are grouped by `event.type` (for example, `file.access` and `file.modified`). The four tabs show counts over time, event type distribution, top entities, module-specific breakdowns and highlighted action counts, plus paged source events. Counts and charts cover all matching documents, while the table shows 25 at a time. Distinct counts use OpenSearch cardinality estimates.

| Tab | Entity / breakdown | Key event columns |
| --- | --- | --- |
| DNS | Question name / response code | Question, record type, response, resolved IPs |
| Network | Destination IP / direction | Source, destination, transport, direction, process |
| Process | Executable / user | Executable, PID, parent, user, command |
| File | Path / directory | Path, action, owner, mode |

Highlighted counts show failed DNS answers, outbound network events, process starts, and file accesses respectively.

The existing Protections tab retains the release YARA catalog and last reported agent inventory; its contract remains in [detection-content-contract.md](detection-content-contract.md).

## Read API

`GET /api/xdr-defense/telemetry` accepts:

- `module`: required; `dns`, `network`, `process`, or `file`.
- `hours`: `1`, `24` (default), or `168`.
- `page`: 1-based, default 1, maximum 400; page size is 25.
- `host`, `type`: optional exact host and event type.
- `search`: optional text search on module-specific keyword fields, host and event type; IP searches use exact source or destination IP.

The response contains `total`, `page`, `pageSize`, `events`, `timeline`, `byType`, `byEntity`, `byHost`, `byFacet`, `uniqueEntities`, `uniqueHosts`, and `highlightCount`. Each event includes its source document and index. The UI limits browsing to the newest 10,000 matches; narrow the filters to inspect older events. There are no write routes.
