# XDR Defense

XDR Defense is a read-only OpenSearch Dashboards plugin for XDR Agent telemetry in `.xdr-agent-telemetry-*`. DNS, Network, Process, and File tabs show activity, key metrics, breakdowns, and recent events. File includes access and integrity events.

![XDR Defense DNS overview with shared search controls, charts, and event table](images/XDR_Defense-overview.png)

The time picker, KQL search, and filter pills apply to every tab. Click chart or table values to add filters; open an event to inspect its Table or JSON view. The read API is `POST /api/xdr-defense/telemetry/search`.

## Install

Build against the same OpenSearch Dashboards version you run. The build uses the adjacent `OpenSearch-Dashboards` source checkout.

```bash
npm run build -- --opensearch-dashboards-version 3.8.0
/path/to/opensearch-dashboards/bin/opensearch-dashboards-plugin install "file://$(realpath build/xdrDefense-3.8.0.zip)"
```

Restart Dashboards and open `/app/xdrDefense`. For this workspace's Docker deployment, see [the local stack guide](../opensearch/README.md).
