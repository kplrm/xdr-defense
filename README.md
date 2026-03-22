# XDR Defense

`xdr-defense` is the OpenSearch Dashboards plugin that manages detection and prevention policy, artifact publishing, threat-intelligence feeds, correlation content, and rollback confirmation workflows for `xdr-agent`.

## Responsibilities

- Manage global operation mode: `detect` or `prevent`
- Manage per-capability toggles for malware, ransomware, memory, rollback, and correlation
- Register and version local artifacts for agent rollout:
  - YARA rule bundles
  - behavioral rule bundles
  - malware hash sets
  - threat-intel packages
- Manage threat-intelligence feed sources and convert synced feeds into local artifacts
- Expose latest artifact manifest for downstream consumers
- Install OpenSearch assets at startup:
  - index templates for alerts, prevention actions, and agent logs
  - ingest pipelines for normalized alert/log ingestion
  - correlation rule definitions for time-window detections
- Confirm rollback actions after ransomware incidents

## UI sections

The plugin UI is organized into five tabs:

1. `Overview`
  - posture cards for mode, artifacts, feeds, and prevention state
  - latest manifest preview
  - correlation content preview
2. `Policy`
  - global detect/prevent mode
  - grouped capability toggles
3. `Artifacts`
  - artifact registry table
  - artifact publishing form
4. `Threat Intel`
  - feed inventory
  - feed registration
  - one-click feed sync to local threat-intel artifact
5. `Response`
  - rollback confirmation workflow
  - last action response preview

## API surface

Base path: `/api/xdr-defense`

### Policy

- `GET /summary`
- `GET /policy`
- `PUT /policy`

### Artifacts

- `GET /artifacts`
- `POST /artifacts`
- `GET /artifacts/manifest/latest`
- `GET /correlation-rules`

### Threat intelligence

- `GET /threat-intel/feeds`
- `POST /threat-intel/feeds`
- `POST /threat-intel/sync`

### Response

- `POST /rollback/confirm`

## Persistence model

The plugin stores its control-plane state in hidden saved object types:

- `xdr-defense-policy`
- `xdr-defense-artifact`
- `xdr-defense-feed`

This keeps state persistent across OpenSearch Dashboards restarts.

## Integration model

- `xdr-agent` remains local-artifact-only and does not pull remote threat feeds directly
- `xdr-defense` is responsible for threat-intelligence source management and artifact publication
- `xdr-manager-plugin` can consume `xdr-defense` APIs as the source of truth for policy and artifact rollout
- Agent-side detections remain single-event focused; OpenSearch performs time-window correlation

## Build from source

From the OpenSearch Dashboards root:

```bash
yarn osd bootstrap --single-version=loose
cd plugins/xdr-defense
yarn lint
yarn build --opensearch-dashboards-version 3.5.0
```

The distributable ZIP is created at:

```bash
build/xdrDefense-3.5.0.zip
```

## Run with xdr-manager-plugin

The custom Dashboards image in the `opensearch` repository installs both plugins:

- `xdr-manager-plugin`
- `xdr-defense`

Build and run them together:

```bash
cd /home/kplrm/github/OpenSearch-Dashboards/plugins/xdr-manager-plugin
yarn build --opensearch-dashboards-version 3.5.0

cd /home/kplrm/github/OpenSearch-Dashboards/plugins/xdr-defense
yarn build --opensearch-dashboards-version 3.5.0

cd /home/kplrm/github/opensearch
docker compose -f docker-compose.yml -f docker-compose.xdr-manager.yml build opensearch-dashboards
docker compose -f docker-compose.yml -f docker-compose.xdr-manager.yml up -d
```

## Notes

- Threat-intel sync currently registers a local artifact and marks the feed sync timestamp; downloading and packaging the actual feed body can be added next
- Correlation rule definitions are exposed by API and embedded into the plugin runtime so they survive packaging
- Startup asset installation is best-effort: failures are logged, but plugin startup continues
