declare const require: any;

const crypto = require('crypto');

const YARA_ROLLOUT_STATUS_INDEX = '.xdr-defense-yara-rollout-status';
const YARA_ROLLOUT_REQUEST_INDEX = '.xdr-defense-yara-rollout-requests';
const AGENT_INDEX = 'xdr-agents';
const STATUS_STALE_MINUTES = 30;
const RULE_HEALTH_INDEX_PREFIX = '.xdr-defense-rule-health';

let yaraRolloutStatusIndexReady = false;
let yaraRolloutStatusIndexEnsureInFlight: Promise<void> | null = null;
let yaraRolloutRequestIndexReady = false;
let yaraRolloutRequestIndexEnsureInFlight: Promise<void> | null = null;

export interface YaraRolloutStatusReport {
  manager_policy_id?: string;
  policy_id?: string;
  agent_id: string;
  agent_hostname?: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  failed_rules?: Array<{ rule_id?: string; status?: string; error_message?: string }>;
  reported_at?: number | string;
}

export interface YaraRolloutStatusRow {
  agent: string;
  policy: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  failed_rule_count?: number;
  last_reported?: string;
  error?: string;
}

export interface YaraRolloutStatusListResponse {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  stale_after_minutes: number;
  items: YaraRolloutStatusRow[];
}

export interface YaraRolloutRequestRecord {
  policy_id: string;
  bundle_version: number;
  generated_at: string;
  requested_at: string;
  rule_count: number;
}

interface StoredYaraRolloutStatusDoc {
  agent_id: string;
  agent_hostname?: string;
  policy_id: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  failed_rule_count?: number;
  last_reported: string;
  error?: string;
  updated_at: string;
}

interface AgentRecord {
  agent_id: string;
  hostname?: string;
  policy_id?: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function parseTime(value?: string): number {
  if (!value) {
    return 0;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function normalizePolicyId(raw: unknown): string {
  const value = String(raw ?? '').trim();
  return value.length > 0 ? value : 'global-default';
}

function normalizeState(raw: unknown): string {
  const value = String(raw ?? '').trim().toLowerCase();
  if (!value) {
    return 'unknown';
  }
  if (['ack', 'acked', 'applied', 'succeeded', 'success', 'ok'].includes(value)) {
    return 'applied';
  }
  if (['partial'].includes(value)) {
    return 'partial';
  }
  if (['failed', 'error'].includes(value)) {
    return 'failed';
  }
  if (['pending', 'in_progress', 'processing'].includes(value)) {
    return 'pending';
  }
  if (['offline', 'unknown', 'offline/unknown'].includes(value)) {
    return 'offline/unknown';
  }
  return value;
}

function normalizeReportedAt(raw: unknown): string {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) {
    const ms = raw > 1_000_000_000_000 ? raw : raw * 1000;
    return new Date(ms).toISOString();
  }
  if (typeof raw === 'string' && raw.trim().length > 0) {
    const numeric = Number(raw);
    if (Number.isFinite(numeric) && numeric > 0) {
      const ms = numeric > 1_000_000_000_000 ? numeric : numeric * 1000;
      return new Date(ms).toISOString();
    }
    const parsed = Date.parse(raw);
    if (Number.isFinite(parsed)) {
      return new Date(parsed).toISOString();
    }
  }
  return nowIso();
}

function docId(agentId: string, policyId: string): string {
  return crypto.createHash('sha256').update(`${agentId}|${policyId}`, 'utf8').digest('hex').slice(0, 40);
}

function requestDocId(policyId: string): string {
  return normalizePolicyId(policyId);
}

function fromUnixTimestamp(input: number): string {
  const numeric = Number(input);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return nowIso();
  }
  const ms = numeric > 1_000_000_000_000 ? numeric : numeric * 1000;
  const parsed = new Date(ms);
  if (Number.isNaN(parsed.getTime())) {
    return nowIso();
  }
  return parsed.toISOString();
}

export function ruleHealthTimestamp(input: unknown): string {
  if (typeof input === 'number') {
    return fromUnixTimestamp(input);
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) {
      return nowIso();
    }
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric)) {
      return fromUnixTimestamp(numeric);
    }
    const parsed = new Date(trimmed);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }
  return nowIso();
}

function ruleHealthIndexFor(reportedAtIso: string): string {
  const datePart = reportedAtIso.slice(0, 10).replace(/-/g, '.');
  if (!datePart || datePart.length !== 10) {
    const nowPart = nowIso().slice(0, 10).replace(/-/g, '.');
    return `${RULE_HEALTH_INDEX_PREFIX}-${nowPart}`;
  }
  return `${RULE_HEALTH_INDEX_PREFIX}-${datePart}`;
}

export function ruleHealthIndexForTimestamp(input: unknown): string {
  return ruleHealthIndexFor(ruleHealthTimestamp(input));
}

function isOfflineOrUnknown(lastReported?: string): boolean {
  const reportedMs = parseTime(lastReported);
  if (reportedMs <= 0) {
    return true;
  }
  const ageMs = Date.now() - reportedMs;
  return ageMs > STATUS_STALE_MINUTES * 60 * 1000;
}

function mapStoredStatusHit(hit: any): StoredYaraRolloutStatusDoc | null {
  const source = hit?._source;
  if (!source) {
    return null;
  }
  const agentId = String(source.agent_id ?? '').trim();
  if (!agentId) {
    return null;
  }
  return {
    agent_id: agentId,
    agent_hostname: source.agent_hostname ? String(source.agent_hostname) : undefined,
    policy_id: normalizePolicyId(source.policy_id),
    state: normalizeState(source.state),
    bundle_version:
      typeof source.bundle_version === 'number' && Number.isFinite(source.bundle_version)
        ? source.bundle_version
        : undefined,
    total_rules:
      typeof source.total_rules === 'number' && Number.isFinite(source.total_rules)
        ? source.total_rules
        : undefined,
    loaded_rules:
      typeof source.loaded_rules === 'number' && Number.isFinite(source.loaded_rules)
        ? source.loaded_rules
        : undefined,
    failed_rule_count:
      typeof source.failed_rule_count === 'number' && Number.isFinite(source.failed_rule_count)
        ? source.failed_rule_count
        : undefined,
    last_reported: String(source.last_reported ?? nowIso()),
    error: source.error ? String(source.error) : undefined,
    updated_at: String(source.updated_at ?? nowIso())
  };
}

function indexExistsResponseToBoolean(response: any): boolean {
  if (typeof response === 'boolean') {
    return response;
  }
  if (typeof response?.body === 'boolean') {
    return response.body;
  }
  return Number(response?.statusCode ?? response?.status) === 200;
}

function hasAlreadyExistsType(errorNode: unknown): boolean {
  if (!errorNode || typeof errorNode !== 'object') {
    return false;
  }

  const node = errorNode as Record<string, unknown>;
  if (String(node.type ?? '').toLowerCase() === 'resource_already_exists_exception') {
    return true;
  }
  if (Array.isArray(node.root_cause) && node.root_cause.some((entry) => hasAlreadyExistsType(entry))) {
    return true;
  }
  return hasAlreadyExistsType(node.caused_by);
}

function isAlreadyExistsError(err: unknown): boolean {
  if (hasAlreadyExistsType((err as any)?.body?.error)) {
    return true;
  }
  if (hasAlreadyExistsType((err as any)?.meta?.body?.error)) {
    return true;
  }

  const msg = String((err as any)?.message ?? err ?? '').toLowerCase();
  return msg.includes('resource_already_exists_exception') || msg.includes('already exists');
}

async function listAgents(client: any): Promise<AgentRecord[]> {
  try {
    const response = await client.search({
      index: AGENT_INDEX,
      size: 10000,
      body: {
        query: { match_all: {} },
        _source: ['agent_id', 'hostname', 'policy_id']
      }
    });
    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    const results: AgentRecord[] = [];
    for (const hit of hits) {
      const source = hit?._source ?? {};
      const agentId = String(source.agent_id ?? hit?._id ?? '').trim();
      if (!agentId) {
        continue;
      }
      results.push({
        agent_id: agentId,
        hostname: source.hostname ? String(source.hostname) : undefined,
        policy_id: source.policy_id ? String(source.policy_id) : undefined
      });
    }
    return results;
  } catch (_err) {
    return [];
  }
}

export function yaraRolloutStatusIndexName(): string {
  return YARA_ROLLOUT_STATUS_INDEX;
}

export function yaraRolloutRequestIndexName(): string {
  return YARA_ROLLOUT_REQUEST_INDEX;
}

export async function ensureYaraRolloutStatusIndex(client: any): Promise<void> {
  if (yaraRolloutStatusIndexReady) {
    return;
  }

  if (!yaraRolloutStatusIndexEnsureInFlight) {
    yaraRolloutStatusIndexEnsureInFlight = (async () => {
      const existsResponse = await client.indices.exists({ index: YARA_ROLLOUT_STATUS_INDEX });
      if (indexExistsResponseToBoolean(existsResponse)) {
        yaraRolloutStatusIndexReady = true;
        return;
      }

      try {
        await client.indices.create({
          index: YARA_ROLLOUT_STATUS_INDEX,
          body: {
            mappings: {
              properties: {
                agent_id: { type: 'keyword' },
                agent_hostname: { type: 'keyword' },
                policy_id: { type: 'keyword' },
                state: { type: 'keyword' },
                bundle_version: { type: 'long' },
                total_rules: { type: 'long' },
                loaded_rules: { type: 'long' },
                failed_rule_count: { type: 'long' },
                last_reported: { type: 'date' },
                error: { type: 'text' },
                updated_at: { type: 'date' }
              }
            }
          }
        });
      } catch (err: any) {
        if (!isAlreadyExistsError(err)) {
          throw err;
        }
      }

      yaraRolloutStatusIndexReady = true;
    })().finally(() => {
      yaraRolloutStatusIndexEnsureInFlight = null;
    });
  }

  return yaraRolloutStatusIndexEnsureInFlight;
}

export async function ensureYaraRolloutRequestIndex(client: any): Promise<void> {
  if (yaraRolloutRequestIndexReady) {
    return;
  }

  if (!yaraRolloutRequestIndexEnsureInFlight) {
    yaraRolloutRequestIndexEnsureInFlight = (async () => {
      const existsResponse = await client.indices.exists({ index: YARA_ROLLOUT_REQUEST_INDEX });
      if (indexExistsResponseToBoolean(existsResponse)) {
        yaraRolloutRequestIndexReady = true;
        return;
      }

      try {
        await client.indices.create({
          index: YARA_ROLLOUT_REQUEST_INDEX,
          body: {
            mappings: {
              properties: {
                policy_id: { type: 'keyword' },
                bundle_version: { type: 'long' },
                generated_at: { type: 'date' },
                requested_at: { type: 'date' },
                rule_count: { type: 'long' }
              }
            }
          }
        });
      } catch (err: any) {
        if (!isAlreadyExistsError(err)) {
          throw err;
        }
      }

      yaraRolloutRequestIndexReady = true;
    })().finally(() => {
      yaraRolloutRequestIndexEnsureInFlight = null;
    });
  }

  return yaraRolloutRequestIndexEnsureInFlight;
}

export async function ingestYaraRolloutStatusReport(
  client: any,
  report: YaraRolloutStatusReport
): Promise<{ accepted: true; index: string; id: string; state: string; last_reported: string }> {
  await ensureYaraRolloutStatusIndex(client);
  const agentId = String(report.agent_id ?? '').trim();
  const policyId = normalizePolicyId(report.manager_policy_id ?? report.policy_id);
  const id = docId(agentId, policyId);
  const state = normalizeState(report.state);
  const lastReported = normalizeReportedAt(report.reported_at);
  const updatedAt = nowIso();
  const failedRuleCount = Array.isArray(report.failed_rules) ? report.failed_rules.length : 0;
  const error = failedRuleCount > 0
    ? report.failed_rules
        ?.map((entry) => String(entry?.error_message ?? '').trim())
        .filter((entry) => entry.length > 0)
        .join(' | ')
    : undefined;

  await client.update({
    index: YARA_ROLLOUT_STATUS_INDEX,
    id,
    refresh: 'wait_for',
    body: {
      doc: {
        agent_id: agentId,
        agent_hostname: report.agent_hostname ? String(report.agent_hostname).trim() || undefined : undefined,
        policy_id: policyId,
        state,
        bundle_version:
          typeof report.bundle_version === 'number' && Number.isFinite(report.bundle_version)
            ? Math.max(0, Math.floor(report.bundle_version))
            : undefined,
        total_rules:
          typeof report.total_rules === 'number' && Number.isFinite(report.total_rules)
            ? Math.max(0, Math.floor(report.total_rules))
            : undefined,
        loaded_rules:
          typeof report.loaded_rules === 'number' && Number.isFinite(report.loaded_rules)
            ? Math.max(0, Math.floor(report.loaded_rules))
            : undefined,
        failed_rule_count: failedRuleCount,
        last_reported: lastReported,
        error: error || undefined,
        updated_at: updatedAt
      },
      doc_as_upsert: true
    }
  });

  return {
    accepted: true,
    index: YARA_ROLLOUT_STATUS_INDEX,
    id,
    state,
    last_reported: lastReported
  };
}

export async function listYaraRolloutStatus(
  client: any,
  input?: { page?: number; pageSize?: number }
): Promise<YaraRolloutStatusListResponse> {
  await ensureYaraRolloutStatusIndex(client);

  const page = Math.max(1, Math.floor(Number(input?.page ?? 1) || 1));
  const pageSize = Math.max(1, Math.min(500, Math.floor(Number(input?.pageSize ?? 20) || 20)));

  let statusHits: any[] = [];
  try {
    const response = await client.search({
      index: YARA_ROLLOUT_STATUS_INDEX,
      size: 10000,
      body: {
        query: { match_all: {} },
        sort: [{ last_reported: { order: 'desc' } }]
      }
    });
    statusHits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
  } catch (_err) {
    statusHits = [];
  }

  const statusDocs = statusHits
    .map((hit) => mapStoredStatusHit(hit))
    .filter((row): row is StoredYaraRolloutStatusDoc => row !== null);

  const statusByAgentPolicy = new Map<string, StoredYaraRolloutStatusDoc>();
  for (const doc of statusDocs) {
    const key = `${doc.agent_id}|${doc.policy_id}`;
    if (!statusByAgentPolicy.has(key)) {
      statusByAgentPolicy.set(key, doc);
    }
  }

  const agents = await listAgents(client);
  const merged: YaraRolloutStatusRow[] = [];

  for (const doc of statusByAgentPolicy.values()) {
    const offlineOrUnknown = isOfflineOrUnknown(doc.last_reported);
    merged.push({
      agent: doc.agent_hostname || doc.agent_id,
      policy: doc.policy_id,
      state: offlineOrUnknown ? 'offline/unknown' : doc.state,
      bundle_version: doc.bundle_version,
      total_rules: doc.total_rules,
      loaded_rules: doc.loaded_rules,
      failed_rule_count: doc.failed_rule_count,
      last_reported: doc.last_reported,
      error: doc.error
    });
  }

  for (const agent of agents) {
    const policyId = normalizePolicyId(agent.policy_id);
    const key = `${agent.agent_id}|${policyId}`;
    if (statusByAgentPolicy.has(key)) {
      continue;
    }

    merged.push({
      agent: agent.hostname || agent.agent_id,
      policy: policyId,
      state: 'offline/unknown',
      error: 'No recent YARA rollout status report from agent.'
    });
  }

  merged.sort((left, right) => {
    const leftTime = parseTime(left.last_reported);
    const rightTime = parseTime(right.last_reported);
    if (leftTime !== rightTime) {
      return rightTime - leftTime;
    }
    return left.agent.localeCompare(right.agent);
  });

  const total = merged.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const clampedPage = Math.min(page, totalPages);
  const start = (clampedPage - 1) * pageSize;

  return {
    page: clampedPage,
    pageSize,
    total,
    totalPages,
    stale_after_minutes: STATUS_STALE_MINUTES,
    items: merged.slice(start, start + pageSize)
  };
}

export async function queueYaraRolloutRequest(
  client: any,
  request: YaraRolloutRequestRecord
): Promise<YaraRolloutRequestRecord> {
  await ensureYaraRolloutRequestIndex(client);
  const record: YaraRolloutRequestRecord = {
    policy_id: normalizePolicyId(request.policy_id),
    bundle_version: Math.max(0, Math.floor(Number(request.bundle_version) || 0)),
    generated_at: String(request.generated_at || nowIso()),
    requested_at: String(request.requested_at || nowIso()),
    rule_count: Math.max(0, Math.floor(Number(request.rule_count) || 0))
  };
  await client.update({
    index: YARA_ROLLOUT_REQUEST_INDEX,
    id: requestDocId(record.policy_id),
    refresh: 'wait_for',
    body: {
      doc: record,
      doc_as_upsert: true
    }
  });
  return record;
}

export async function getYaraRolloutRequest(client: any, policyId: string): Promise<YaraRolloutRequestRecord | null> {
  await ensureYaraRolloutRequestIndex(client);
  try {
    const response = await client.get({ index: YARA_ROLLOUT_REQUEST_INDEX, id: requestDocId(policyId) });
    const source = response?.body?._source ?? response?._source;
    if (!source) {
      return null;
    }
    return {
      policy_id: normalizePolicyId(source.policy_id),
      bundle_version: Math.max(0, Math.floor(Number(source.bundle_version) || 0)),
      generated_at: String(source.generated_at ?? nowIso()),
      requested_at: String(source.requested_at ?? nowIso()),
      rule_count: Math.max(0, Math.floor(Number(source.rule_count) || 0))
    };
  } catch (_err) {
    return null;
  }
}