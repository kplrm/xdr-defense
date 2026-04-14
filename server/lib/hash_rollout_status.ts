declare const require: any;

const crypto = require('crypto');

const HASH_ROLLOUT_STATUS_INDEX = 'xdr-defense-hash-rollout-status';
const AGENT_INDEX = 'xdr-agents';
const STATUS_STALE_MINUTES = 30;

let hashRolloutStatusIndexReady = false;
let hashRolloutStatusIndexEnsureInFlight: Promise<void> | null = null;

export interface HashRolloutStatusReport {
  agent_id: string;
  policy_id?: string;
  state: string;
  full_bundle_version?: number;
  custom_bundle_version?: number;
  reported_at?: number | string;
  error?: string;
  agent_hostname?: string;
}

export interface HashRolloutStatusRow {
  agent: string;
  policy: string;
  state: string;
  full_bundle_version?: number;
  custom_bundle_version?: number;
  last_reported?: string;
  error?: string;
}

export interface HashRolloutStatusListResponse {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  stale_after_minutes: number;
  items: HashRolloutStatusRow[];
}

interface StoredHashRolloutStatusDoc {
  agent_id: string;
  agent_hostname?: string;
  policy_id: string;
  state: string;
  full_bundle_version?: number;
  custom_bundle_version?: number;
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

function isOfflineOrUnknown(lastReported?: string): boolean {
  const reportedMs = parseTime(lastReported);
  if (reportedMs <= 0) {
    return true;
  }

  const ageMs = Date.now() - reportedMs;
  return ageMs > STATUS_STALE_MINUTES * 60 * 1000;
}

function mapStoredStatusHit(hit: any): StoredHashRolloutStatusDoc | null {
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
    full_bundle_version:
      typeof source.full_bundle_version === 'number' && Number.isFinite(source.full_bundle_version)
        ? source.full_bundle_version
        : undefined,
    custom_bundle_version:
      typeof source.custom_bundle_version === 'number' && Number.isFinite(source.custom_bundle_version)
        ? source.custom_bundle_version
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

export function hashRolloutStatusIndexName(): string {
  return HASH_ROLLOUT_STATUS_INDEX;
}

export async function ensureHashRolloutStatusIndex(client: any): Promise<void> {
  if (hashRolloutStatusIndexReady) {
    return;
  }

  if (!hashRolloutStatusIndexEnsureInFlight) {
    hashRolloutStatusIndexEnsureInFlight = (async () => {
      const existsResponse = await client.indices.exists({ index: HASH_ROLLOUT_STATUS_INDEX });
      if (indexExistsResponseToBoolean(existsResponse)) {
        hashRolloutStatusIndexReady = true;
        return;
      }

      try {
        await client.indices.create({
          index: HASH_ROLLOUT_STATUS_INDEX,
          body: {
            mappings: {
              properties: {
                agent_id: { type: 'keyword' },
                agent_hostname: { type: 'keyword' },
                policy_id: { type: 'keyword' },
                state: { type: 'keyword' },
                full_bundle_version: { type: 'long' },
                custom_bundle_version: { type: 'long' },
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

      hashRolloutStatusIndexReady = true;
    })().finally(() => {
      hashRolloutStatusIndexEnsureInFlight = null;
    });
  }

  return hashRolloutStatusIndexEnsureInFlight;
}

export async function ingestHashRolloutStatusReport(
  client: any,
  report: HashRolloutStatusReport
): Promise<{ accepted: true; index: string; id: string; state: string; last_reported: string }> {
  await ensureHashRolloutStatusIndex(client);

  const agentId = String(report.agent_id ?? '').trim();
  const policyId = normalizePolicyId(report.policy_id);
  const id = docId(agentId, policyId);
  const state = normalizeState(report.state);
  const lastReported = normalizeReportedAt(report.reported_at);
  const updatedAt = nowIso();

  await client.update({
    index: HASH_ROLLOUT_STATUS_INDEX,
    id,
    refresh: 'wait_for',
    body: {
      doc: {
        agent_id: agentId,
        agent_hostname: report.agent_hostname ? String(report.agent_hostname).trim() || undefined : undefined,
        policy_id: policyId,
        state,
        full_bundle_version:
          typeof report.full_bundle_version === 'number' && Number.isFinite(report.full_bundle_version)
            ? Math.max(0, Math.floor(report.full_bundle_version))
            : undefined,
        custom_bundle_version:
          typeof report.custom_bundle_version === 'number' && Number.isFinite(report.custom_bundle_version)
            ? Math.max(0, Math.floor(report.custom_bundle_version))
            : undefined,
        last_reported: lastReported,
        error: report.error ? String(report.error).trim() || undefined : undefined,
        updated_at: updatedAt
      },
      doc_as_upsert: true
    }
  });

  return {
    accepted: true,
    index: HASH_ROLLOUT_STATUS_INDEX,
    id,
    state,
    last_reported: lastReported
  };
}

export async function listHashRolloutStatus(
  client: any,
  input?: { page?: number; pageSize?: number }
): Promise<HashRolloutStatusListResponse> {
  await ensureHashRolloutStatusIndex(client);

  const page = Math.max(1, Math.floor(Number(input?.page ?? 1) || 1));
  const pageSize = Math.max(1, Math.min(500, Math.floor(Number(input?.pageSize ?? 20) || 20)));

  let statusHits: any[] = [];
  try {
    const response = await client.search({
      index: HASH_ROLLOUT_STATUS_INDEX,
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
    .filter((row): row is StoredHashRolloutStatusDoc => row !== null);

  const statusByAgentPolicy = new Map<string, StoredHashRolloutStatusDoc>();
  for (const doc of statusDocs) {
    const key = `${doc.agent_id}|${doc.policy_id}`;
    if (!statusByAgentPolicy.has(key)) {
      statusByAgentPolicy.set(key, doc);
    }
  }

  const agents = await listAgents(client);
  const merged: HashRolloutStatusRow[] = [];

  for (const [key, doc] of statusByAgentPolicy.entries()) {
    const offlineOrUnknown = isOfflineOrUnknown(doc.last_reported);
    merged.push({
      agent: doc.agent_hostname || doc.agent_id,
      policy: doc.policy_id,
      state: offlineOrUnknown ? 'offline/unknown' : doc.state,
      full_bundle_version: doc.full_bundle_version,
      custom_bundle_version: doc.custom_bundle_version,
      last_reported: doc.last_reported,
      error: doc.error
    });

    statusByAgentPolicy.delete(key);
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
      last_reported: undefined,
      error: 'No recent rollout status report from agent.'
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
  const items = merged.slice(start, start + pageSize);

  return {
    page: clampedPage,
    pageSize,
    total,
    totalPages,
    stale_after_minutes: STATUS_STALE_MINUTES,
    items
  };
}
