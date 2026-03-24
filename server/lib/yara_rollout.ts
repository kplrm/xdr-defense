declare const require: any;

const crypto = require('crypto');

export type RolloutAction = 'activate' | 'deactivate' | 'delete';
export type RolloutStatus = 'pending' | 'acknowledged' | 'failed';

export interface AgentTarget {
  agent_id: string;
  hostname?: string;
  policy_id?: string;
  last_seen?: string;
}

export interface RolloutCommandRecord {
  command_id: string;
  command_key: string;
  dispatch_version: string;
  agent_id: string;
  agent_hostname?: string;
  rule_id: string;
  rule_name: string;
  action: RolloutAction;
  status: RolloutStatus;
  attempts: number;
  first_dispatched_at: string;
  last_dispatched_at: string;
  acknowledged_at?: string;
  failure_reason?: string;
}

export interface RuleRolloutSummary {
  pending: number;
  acknowledged: number;
  failed: number;
  last_action?: RolloutAction;
  last_dispatched_at?: string;
}

export interface RolloutStatusResponse {
  summary: {
    total_commands: number;
    pending: number;
    acknowledged: number;
    failed: number;
    retryable: number;
    stale_timeout_minutes: number;
    generated_at: string;
  };
  failures: Array<RolloutCommandRecord & { retryable: boolean }>;
  rules: Record<string, RuleRolloutSummary>;
}

const ROLLOUT_INDEX = 'xdr-defense-yara-rollouts';
const AGENT_INDEX = 'xdr-agents';
const STALE_PENDING_MINUTES = 10;

function nowIso(): string {
  return new Date().toISOString();
}

function commandKey(agentId: string, ruleId: string, action: RolloutAction, dispatchVersion: string): string {
  return `${agentId}|${ruleId}|${action}|${dispatchVersion}`;
}

function commandIdFor(key: string): string {
  return crypto.createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 32);
}

function parseDate(input?: string): number {
  if (!input) {
    return 0;
  }
  const ms = Date.parse(input);
  return Number.isFinite(ms) ? ms : 0;
}

function recordRecency(record: RolloutCommandRecord): number {
  const last = parseDate(record.last_dispatched_at);
  if (last > 0) {
    return last;
  }
  return parseDate(record.first_dispatched_at);
}

function latestStateKey(record: RolloutCommandRecord): string {
  return `${record.agent_id}|${record.rule_id}`;
}

function collapseToLatestState(records: RolloutCommandRecord[]): RolloutCommandRecord[] {
  const latest = new Map<string, RolloutCommandRecord>();

  for (const record of records) {
    const key = latestStateKey(record);
    const existing = latest.get(key);
    if (!existing) {
      latest.set(key, record);
      continue;
    }

    if (recordRecency(record) >= recordRecency(existing)) {
      latest.set(key, record);
    }
  }

  return Array.from(latest.values());
}

export function rolloutIndexName(): string {
  return ROLLOUT_INDEX;
}

export async function ensureRolloutIndex(client: any): Promise<void> {
  try {
    await client.indices.create({
      index: ROLLOUT_INDEX,
      body: {
        mappings: {
          properties: {
            command_id: { type: 'keyword' },
            command_key: { type: 'keyword' },
            dispatch_version: { type: 'keyword' },
            agent_id: { type: 'keyword' },
            agent_hostname: { type: 'keyword' },
            rule_id: { type: 'keyword' },
            rule_name: { type: 'keyword' },
            action: { type: 'keyword' },
            status: { type: 'keyword' },
            attempts: { type: 'integer' },
            first_dispatched_at: { type: 'date' },
            last_dispatched_at: { type: 'date' },
            acknowledged_at: { type: 'date' },
            failure_reason: { type: 'text' }
          }
        }
      }
    });
  } catch (_err) {
    // Index likely already exists.
  }
}

function isRetryable(entry: RolloutCommandRecord): boolean {
  if (entry.status === 'failed') {
    return true;
  }
  if (entry.status !== 'pending') {
    return false;
  }

  const ageMs = Date.now() - parseDate(entry.last_dispatched_at);
  return ageMs > STALE_PENDING_MINUTES * 60_000;
}

function mapHit(hit: any): RolloutCommandRecord | null {
  const source = hit?._source;
  if (!source) {
    return null;
  }
  return {
    command_id: String(source.command_id ?? hit?._id ?? ''),
    command_key: String(source.command_key ?? ''),
    dispatch_version: String(source.dispatch_version ?? ''),
    agent_id: String(source.agent_id ?? ''),
    agent_hostname: source.agent_hostname ? String(source.agent_hostname) : undefined,
    rule_id: String(source.rule_id ?? ''),
    rule_name: String(source.rule_name ?? ''),
    action: String(source.action ?? 'activate') as RolloutAction,
    status: String(source.status ?? 'pending') as RolloutStatus,
    attempts: Number(source.attempts ?? 1),
    first_dispatched_at: String(source.first_dispatched_at ?? nowIso()),
    last_dispatched_at: String(source.last_dispatched_at ?? nowIso()),
    acknowledged_at: source.acknowledged_at ? String(source.acknowledged_at) : undefined,
    failure_reason: source.failure_reason ? String(source.failure_reason) : undefined
  };
}

export async function listEnrolledAgents(client: any): Promise<AgentTarget[]> {
  try {
    const response = await client.search({
      index: AGENT_INDEX,
      size: 10000,
      body: {
        query: { match_all: {} },
        _source: ['agent_id', 'hostname', 'policy_id', 'last_seen', 'lastSeen', 'status']
      }
    });

    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    const results: AgentTarget[] = [];
    for (const hit of hits) {
      const source = hit?._source ?? {};
      const agentId = String(source.agent_id ?? hit?._id ?? '').trim();
      if (!agentId) {
        continue;
      }
      results.push({
        agent_id: agentId,
        hostname: source.hostname ? String(source.hostname) : undefined,
        policy_id: source.policy_id ? String(source.policy_id) : undefined,
        last_seen: source.last_seen ? String(source.last_seen) : source.lastSeen ? String(source.lastSeen) : undefined
      });
    }
    return results;
  } catch (_err) {
    return [];
  }
}

export async function dispatchRolloutForAgents(
  client: any,
  agents: AgentTarget[],
  rule: { id: string; name: string; updatedAt: string },
  action: RolloutAction
): Promise<{ dispatched: number; deduplicated: number }> {
  await ensureRolloutIndex(client);
  let dispatched = 0;
  let deduplicated = 0;
  const dispatchVersion = String(rule.updatedAt || nowIso());

  for (const agent of agents) {
    const key = commandKey(agent.agent_id, rule.id, action, dispatchVersion);
    const commandId = commandIdFor(key);

    const doc = {
      command_id: commandId,
      command_key: key,
      dispatch_version: dispatchVersion,
      agent_id: agent.agent_id,
      agent_hostname: agent.hostname,
      rule_id: rule.id,
      rule_name: rule.name,
      action,
      status: 'pending' as RolloutStatus,
      attempts: 1,
      first_dispatched_at: nowIso(),
      last_dispatched_at: nowIso(),
      failure_reason: undefined
    };

    try {
      await client.create({
        index: ROLLOUT_INDEX,
        id: commandId,
        refresh: 'wait_for',
        body: doc
      });
      dispatched += 1;
    } catch (_err) {
      deduplicated += 1;
      await client.update({
        index: ROLLOUT_INDEX,
        id: commandId,
        refresh: 'wait_for',
        body: {
          script: {
            source:
              'ctx._source.last_dispatched_at = params.now; ' +
              'if (ctx._source.status != "acknowledged") { ctx._source.status = "pending"; } ' +
              'ctx._source.attempts = (ctx._source.attempts != null ? ctx._source.attempts : 1);',
            params: { now: nowIso() }
          },
          upsert: doc
        }
      });
    }
  }

  return { dispatched, deduplicated };
}

export async function listRolloutStatus(client: any): Promise<RolloutStatusResponse> {
  await ensureRolloutIndex(client);

  let hits: any[] = [];
  try {
    const response = await client.search({
      index: ROLLOUT_INDEX,
      size: 500,
      sort: ['last_dispatched_at:desc'],
      body: {
        query: { match_all: {} }
      }
    });
    hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
  } catch (_err) {
    hits = [];
  }

  const allRecords = hits
    .map((hit) => mapHit(hit))
    .filter((entry): entry is RolloutCommandRecord => entry !== null);

  // Surface only the latest rollout state per agent+rule to avoid stale historical
  // commands from being treated as active failures forever.
  const records = collapseToLatestState(allRecords);

  const summary = {
    total_commands: records.length,
    pending: 0,
    acknowledged: 0,
    failed: 0,
    retryable: 0,
    stale_timeout_minutes: STALE_PENDING_MINUTES,
    generated_at: nowIso()
  };

  const failures: Array<RolloutCommandRecord & { retryable: boolean }> = [];
  const ruleStatus: Record<string, RuleRolloutSummary> = {};

  for (const record of records) {
    if (record.status === 'pending') {
      summary.pending += 1;
    } else if (record.status === 'acknowledged') {
      summary.acknowledged += 1;
    } else {
      summary.failed += 1;
    }

    const retryable = isRetryable(record);
    if (retryable) {
      summary.retryable += 1;
      failures.push({
        ...record,
        retryable,
        failure_reason: record.failure_reason ??
          (record.status === 'pending'
            ? `No ACK received after ${STALE_PENDING_MINUTES} minutes; agent may be offline.`
            : record.failure_reason)
      });
    }

    if (!ruleStatus[record.rule_id]) {
      ruleStatus[record.rule_id] = {
        pending: 0,
        acknowledged: 0,
        failed: 0,
        last_action: record.action,
        last_dispatched_at: record.last_dispatched_at
      };
    }
    if (record.status === 'pending') {
      ruleStatus[record.rule_id].pending += 1;
    } else if (record.status === 'acknowledged') {
      ruleStatus[record.rule_id].acknowledged += 1;
    } else {
      ruleStatus[record.rule_id].failed += 1;
    }

    const currentLast = parseDate(ruleStatus[record.rule_id].last_dispatched_at);
    const nextLast = parseDate(record.last_dispatched_at);
    if (nextLast >= currentLast) {
      ruleStatus[record.rule_id].last_action = record.action;
      ruleStatus[record.rule_id].last_dispatched_at = record.last_dispatched_at;
    }
  }

  failures.sort((a, b) => parseDate(b.last_dispatched_at) - parseDate(a.last_dispatched_at));

  return {
    summary,
    failures,
    rules: ruleStatus
  };
}

export async function retryRetryableCommands(client: any): Promise<{ retried: number }> {
  await ensureRolloutIndex(client);
  const snapshot = await listRolloutStatus(client);
  const retryableIds = snapshot.failures.filter((entry) => entry.retryable).map((entry) => entry.command_id);

  let retried = 0;
  for (const commandId of retryableIds) {
    await client.update({
      index: ROLLOUT_INDEX,
      id: commandId,
      refresh: 'wait_for',
      body: {
        script: {
          source:
            'ctx._source.status = "pending"; ' +
            'ctx._source.failure_reason = null; ' +
            'ctx._source.last_dispatched_at = params.now; ' +
            'ctx._source.attempts = (ctx._source.attempts != null ? ctx._source.attempts + 1 : 2);',
          params: { now: nowIso() }
        }
      }
    });
    retried += 1;
  }

  return { retried };
}

export async function acknowledgeRollout(
  client: any,
  ack: {
    command_id?: string;
    command_key?: string;
    agent_id: string;
    rule_id?: string;
    action?: RolloutAction;
    dispatch_version?: string;
    status: 'acknowledged' | 'failed';
    reason?: string;
  }
): Promise<{ updated: boolean; reason?: string }> {
  await ensureRolloutIndex(client);

  let commandId = String(ack.command_id ?? '').trim();
  if (!commandId) {
    if (ack.command_key) {
      commandId = commandIdFor(String(ack.command_key));
    } else if (ack.rule_id && ack.action && ack.dispatch_version) {
      commandId = commandIdFor(commandKey(ack.agent_id, ack.rule_id, ack.action, ack.dispatch_version));
    }
  }

  if (!commandId) {
    return { updated: false, reason: 'Unable to determine command identity for ACK.' };
  }

  try {
    await client.update({
      index: ROLLOUT_INDEX,
      id: commandId,
      refresh: 'wait_for',
      body: {
        script: {
          source:
            'ctx._source.status = params.status; ' +
            'ctx._source.acknowledged_at = params.now; ' +
            'ctx._source.failure_reason = params.reason;',
          params: {
            status: ack.status,
            now: nowIso(),
            reason: ack.status === 'failed' ? String(ack.reason ?? 'agent reported failure') : null
          }
        }
      }
    });
    return { updated: true };
  } catch (_err) {
    return { updated: false, reason: 'Command not found for ACK.' };
  }
}
