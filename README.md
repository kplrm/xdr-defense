# xdr-defense

XDR Defense explores DNS, network, process and file telemetry collected by XDR Agent in OpenSearch Dashboards. It uses Discover's time picker, KQL input and filter controls.

See [the telemetry dashboard contract](docs/telemetry-dashboard.md).

```bash
npm test
npm run build -- --opensearch-dashboards-version 3.5.0
```

Builds use a temporary Dashboards copy and leave the upstream checkout untouched.
