# Telemetry explorer

XDR Defense reads `.xdr-agent-telemetry-*` through the current Dashboards user's OpenSearch permissions. DNS, Network, Process and File are the four tabs. The File tab selects `event.module=telemetry.file`; `event.type` distinguishes access from integrity changes.

The shared controls above the tabs are Dashboards' SearchBar: a relative or absolute date picker, KQL query input, and filter pills. Filters added through the editor, chart values, event cells or the event detail table can be disabled, edited or removed. Enabled filters and the time range apply to every tab. The event flyout opens on its field/value Table view and has a JSON tab.

| Tab | Entity / breakdown | Key event columns |
| --- | --- | --- |
| DNS | Question name / response code | Question, record type, response, answers |
| Network | Destination IP / direction | Source, destination, transport, direction, process |
| Process | Executable / user | Executable, PID, parent, user, command |
| File | Path / directory | Path, action, owner, mode |

Counts and charts cover all matching documents. Distinct counts use OpenSearch cardinality estimates; event tables page through the newest 10,000 matches.

## Read API

`POST /api/xdr-defense/telemetry/search` accepts JSON with `module` (`dns`, `network`, `process`, or `file`), `from`, `to`, `page` (1-based), and `query`. The Dashboards data plugin compiles KQL and enabled filter pills into the query. Defense always adds the selected module and time range on the server, and searches only `.xdr-agent-telemetry-*`. The route performs no writes.

The response contains `total`, `page`, `pageSize`, `events`, `timeline`, `byType`, `byEntity`, `byHost`, `byFacet`, `uniqueEntities`, `uniqueHosts`, and `highlightCount`. Each event includes its source document and index.
