declare const require: any;

import type { ProtectionNamespace } from './protection_registry';

const crypto = require('crypto');

const AGENT_INDEX = 'xdr-agents';
const STATUS_STALE_MINUTES = 30;

interface NamespaceRolloutConfig {
  statusIndex: string;
}

const CONFIG_BY_NAMESPACE: Record<ProtectionNamespace, NamespaceRolloutConfig> = {
  memory: { statusIndex: 'xdr-defense-memory-rollout-status' },
  ransomware: { statusIndex: 'xdr-defense-ransomware-rollout-status' }
};

const protectionRolloutStatusIndexReady: Record<ProtectionNamespace, boolean> = {
  memory: false,
  ransomware: false
};

const protectionRolloutStatusEnsureInFlight: Record<ProtectionNamespace, Promise<void> | null> = {
  memory: null,
  ransomware: null
};

export interface ProtectionRolloutStatusReport {
  agent_id: string;
  policy_id?: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  reported_at?: number | string;
  error?: string;
  agent_hostname?: string;
}

interface StoredRolloutStatusDoc {
  agent_id: string;
  agent_hostname?: string;
  policy_id: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  last_reported: string;
  error?: string;
  updated_at: string;
}

interface AgentRecord {
  agent_id: string;
  hostname?: string;
  policy_id?: string;
}

export interface ProtectionRolloutStatusRow {
  agent: string;
  policy: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  last_reported?: string;
  error?: string;
}

export interface ProtectionRolloutStatusListResponse {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  stale_after_minutes: number;
  items: ProtectionRolloutStatusRow[];
}

function config(namespace: ProtectionNamespace): NamespaceRolloutConfig {
  return CONFIG_BY_NAMESPACE[namespace];
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
  if (['partial'].includes(value)) {
    return 'partial';
  }
  if (['pending', 'in_progress', 'processing'].includes(value)) {
    return 'pending';
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

function mapStoredStatusHit(hit: any): StoredRolloutStatusDoc | null {
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

export async function ensureProtectionRolloutStatusIndex(client: any, namespace: ProtectionNamespace): Promise<void> {
  if (protectionRolloutStatusIndexReady[namespace]) {
    return;
  }

  if (protectionRolloutStatusEnsureInFlight[namespace]) {
    return protectionRolloutStatusEnsureInFlight[namespace] as Promise<void>;
  }

  const nsConfig = config(namespace);

  protectionRolloutStatusEnsureInFlight[namespace] = (async () => {
    const existsResponse = await client.indices.exists({ index: nsConfig.statusIndex });
    if (indexExistsResponseToBoolean(existsResponse)) {
      protectionRolloutStatusIndexReady[namespace] = true;
      return;
    }

    try {
      await client.indices.create({
        index: nsConfig.statusIndex,
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

    protectionRolloutStatusIndexReady[namespace] = true;
  })().finally(() => {
    protectionRolloutStatusEnsureInFlight[namespace] = null;
  });

  return protectionRolloutStatusEnsureInFlight[namespace] as Promise<void>;
}

export async function ingestProtectionRolloutStatusReport(
  client: any,
  namespace: ProtectionNamespace,
  report: ProtectionRolloutStatusReport
): Promise<{ accepted: true; index: string; id: string; state: string; last_reported: string }> {
  const nsConfig = config(namespace);
  await ensureProtectionRolloutStatusIndex(client, namespace);

  const agentId = String(report.agent_id ?? '').trim();
  const policyId = normalizePolicyId(report.policy_id);
  const id = docId(agentId, policyId);
  const state = normalizeState(report.state);
  const lastReported = normalizeReportedAt(report.reported_at);

  await client.update({
    index: nsConfig.statusIndex,
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
        last_reported: lastReported,
        error: report.error ? String(report.error).trim() || undefined : undefined,
        updated_at: nowIso()
      },
      doc_as_upsert: true
    }
  });

  return {
    accepted: true,
    index: nsConfig.statusIndex,
    id,
    state,
    last_reported: lastReported
  };
}

export async function listProtectionRolloutStatus(
  client: any,
  namespace: ProtectionNamespace,
  input?: { page?: number; pageSize?: number }
): Promise<ProtectionRolloutStatusListResponse> {
  const nsConfig = config(namespace);
  await ensureProtectionRolloutStatusIndex(client, namespace);

  const page = Math.max(1, Math.floor(Number(input?.page ?? 1) || 1));
  const pageSize = Math.max(1, Math.min(500, Math.floor(Number(input?.pageSize ?? 20) || 20)));

  let statusHits: any[] = [];
  try {
    const response = await client.search({
      index: nsConfig.statusIndex,
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
    .filter((row): row is StoredRolloutStatusDoc => row !== null);

  const statusByAgentPolicy = new Map<string, StoredRolloutStatusDoc>();
  for (const doc of statusDocs) {
    const key = `${doc.agent_id}|${doc.policy_id}`;
    if (!statusByAgentPolicy.has(key)) {
      statusByAgentPolicy.set(key, doc);
    }
  }

  const agents = await listAgents(client);
  const merged: ProtectionRolloutStatusRow[] = [];

  for (const doc of statusByAgentPolicy.values()) {
    merged.push({
      agent: doc.agent_hostname || doc.agent_id,
      policy: doc.policy_id,
      state: isOfflineOrUnknown(doc.last_reported) ? 'offline/unknown' : doc.state,
      bundle_version: doc.bundle_version,
      total_rules: doc.total_rules,
      loaded_rules: doc.loaded_rules,
      last_reported: doc.last_reported,
      error: doc.error
    });
  }

  const seen = new Set<string>([...statusByAgentPolicy.keys()]);
  for (const agent of agents) {
    const policyId = normalizePolicyId(agent.policy_id);
    const key = `${agent.agent_id}|${policyId}`;
    if (seen.has(key)) {
      continue;
    }
    merged.push({
      agent: agent.hostname || agent.agent_id,
      policy: policyId,
      state: 'offline/unknown',
      error: 'No rollout status reported yet.'
    });
  }

  merged.sort((left, right) => {
    if (left.policy !== right.policy) {
      return left.policy.localeCompare(right.policy);
    }
    return left.agent.localeCompare(right.agent);
  });

  const total = merged.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const start = (page - 1) * pageSize;
  const items = merged.slice(start, start + pageSize);

  return {
    page,
    pageSize,
    total,
    totalPages,
    stale_after_minutes: STATUS_STALE_MINUTES,
    items
  };
}
