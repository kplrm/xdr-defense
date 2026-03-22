# Defense Posture Rollout Contract

## Posture Document

Per manager policy ID, xdr-defense is authoritative for defense posture:

```json
{
  "manager_policy_id": "default-endpoint",
  "mode": "detect",
  "capabilities": {
    "malware.hash_detection": true,
    "memory.fileless": true,
    "prevention.enabled": false
  },
  "updatedAt": "2026-03-22T14:00:00Z",
  "version": 5
}
```

## Agent Fetch Endpoint

`GET /api/xdr-defense/policy-overlays/{managerPolicyID}`

- Used by xdr-agent poller to fetch latest posture for its assigned `policy_id`.
- Agent compares `version` with locally cached posture.

## Rollout Creation

When posture is updated from UI, xdr-defense saves posture and creates/updates rollout tracking for that policy+version.

`PUT /api/xdr-defense/policy-overlays/{managerPolicyID}` request body adds:

```json
{
  "mode": "detect",
  "capabilities": {},
  "target_agent_ids": ["agent-1", "agent-2"]
}
```

Response includes rollout summary:

```json
{
  "manager_policy_id": "default-endpoint",
  "mode": "detect",
  "capabilities": {},
  "updatedAt": "...",
  "version": 5,
  "rollout": {
    "policy_id": "default-endpoint",
    "posture_version": 5,
    "target_agents": 2,
    "acked_agents": 1,
    "pending_agents": ["agent-2"]
  }
}
```

## Agent Acknowledgement Endpoint

`POST /api/xdr-defense/policy-rollouts/ack`

```json
{
  "agent_id": "agent-1",
  "policy_id": "default-endpoint",
  "posture_version": 5,
  "hostname": "srv-1"
}
```

Ack marks agent delivery as confirmed for `policy_id + posture_version`.

## Rollout Status Endpoint

`GET /api/xdr-defense/policy-rollouts/{managerPolicyID}/latest`

Returns latest rollout status for policy:

```json
{
  "policy_id": "default-endpoint",
  "posture_version": 5,
  "updated_at": "...",
  "target_agent_ids": ["agent-1", "agent-2"],
  "acked_agent_ids": ["agent-1"],
  "pending_agent_ids": ["agent-2"]
}
```

## Retry Endpoint

`POST /api/xdr-defense/policy-rollouts/{managerPolicyID}/retry`

```json
{
  "agent_ids": ["agent-2"]
}
```

This marks a retry request timestamp for pending agents. Agents still pull posture asynchronously.

## Agent Local Persistence

xdr-agent stores last received posture locally under a state file.
- On startup, it loads cached posture and applies it before runtime starts.
- This ensures posture survives host reboot while disconnected from control plane.
