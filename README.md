# xdr-defense

XDR Defense explores agent DNS, network, process, and file telemetry and provides read-only access to the YARA rules and protection inventory included in agent releases.

Rules are updated by installing a new agent release. Policy grouping and fleet upgrades belong to Coordinator; alert investigation belongs to Visualizer. Ransomware, memory protection and behavioral rules are future work.

Interfaces: [telemetry explorer](docs/telemetry-dashboard.md) and [protection inventory](docs/detection-content-contract.md).

```bash
python3 scripts/prepare_catalog.py --agent-root ../xdr-agent
npm test
npm run build -- --opensearch-dashboards-version 3.5.0
```

Builds use a temporary Dashboards copy and do not write to the upstream workspace checkout. `OSD_ROOT` can select another source checkout.
