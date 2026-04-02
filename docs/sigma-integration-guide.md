# Sigma And Correlation Split

This note explains the intended boundary between behavioral content on the agent and event correlation in OpenSearch.

## Design Decision

- `xdr-agent` should stay focused on single-event detection and prevention.
- OpenSearch should own time-window correlation, aggregation, and cross-event analytics.

That split keeps endpoint behavior deterministic and avoids pushing backend-scale correlation logic into every host.

## What Belongs On The Agent

- YARA matching
- hash matching
- behavioral evaluations that can be decided from the local event or narrow local context
- prevention decisions driven by current posture

## What Belongs In OpenSearch

- time-window correlation
- multi-host or fleet-wide pattern detection
- historical aggregation
- downstream response orchestration and alert routing

## Practical Rule

If a detection requires broad historical context or aggregation, keep it out of the agent runtime and express it as a backend correlation workflow.

If a rule can be evaluated deterministically from the current event stream on-host, it can remain an endpoint concern.

## Documentation Rule

Do not use this file as a second protocol contract. Update `detection-content-contract.md` when agent-facing bundle or rollout behavior changes.
- Detection conditions → Time-window aggregations in OpenSearch
- Correlation rules → POST to Security Analytics API or UI

### Q: What if OpenSearch goes down?

**A**: Agent continues shipping events to a buffer/queue. Alerts are **not** lost; they queue until connectivity restored. Single-event detections remain local to the agent.

### Q: Can I use SIGMA in Splunk/ELK instead?

**A**: Yes. Replace OpenSearch with your SIEM. The agent sends normalized ECS events; any SIEM can ingest and correlate via SIGMA or native rules.

---

**Last Updated**: 2026-03-22  
**Status**: Integration guide complete; ready for threat team implementation
