declare const require: any;

import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';
import { getSigningPrivateKey } from './signing_keys';

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

export type ProtectionNamespace = 'memory' | 'ransomware';
export type ProtectionRuleSource = 'custom' | 'capa-curated' | 'falcosecurity-curated' | 'tracee-curated';

export interface ProtectionSyncStep {
  stage: string;
  message: string;
  at: string;
  details?: Record<string, unknown>;
}

export interface ProtectionSyncSourceBreakdown {
  source: string;
  attempted: number;
  imported: number;
  unchanged: number;
}

export interface ProtectionSyncResult {
  imported: number;
  unchanged: number;
  attempted: number;
  source: string;
  source_name: string;
  index_name: string;
  upstream_total_rules: number;
  upstream_candidate_rules?: number;
  curated_rules: number;
  steps: ProtectionSyncStep[];
  source_breakdown: ProtectionSyncSourceBreakdown[];
}

export interface ProtectionRuleValidation {
  status: 'valid' | 'invalid';
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

export interface SourceMetadata {
  provider: string;
  feed: string;
  upstream_url: string;
  upstream_id: string;
  synced_at: string;
}

export interface LicenseMetadata {
  name?: string;
  url?: string;
}

export interface ProtectionRuleRecord {
  id: string;
  name: string;
  source: ProtectionRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  updatedAt: string;
  validation: ProtectionRuleValidation;
  source_metadata?: SourceMetadata;
  license_metadata?: LicenseMetadata;
}

export interface ProtectionRuleSummary {
  id: string;
  name: string;
  source: ProtectionRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  updatedAt: string;
  validation: ProtectionRuleValidation;
  source_metadata?: SourceMetadata;
  license_metadata?: LicenseMetadata;
}

interface ProtectionIndexDocument {
  name: string;
  source: ProtectionRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  updated_at: string;
  validation: ProtectionRuleValidation;
  source_metadata?: SourceMetadata;
  license_metadata?: LicenseMetadata;
}

export interface ProtectionListResponse {
  rules: ProtectionRuleSummary[];
  page: number;
  pageSize: number;
  total: number;
}

interface PersistedBundleState {
  bundle_version: number;
  generated_at: string;
  content_digest: string;
}

interface PersistedBundleStateFile {
  version: 1;
  bundleStates: Record<string, PersistedBundleState>;
}

interface CuratedRuleInput {
  id: string;
  name: string;
  severity: string;
  tags: string[];
  content: string;
  source?: ProtectionRuleSource;
  source_metadata: SourceMetadata;
  license_metadata?: LicenseMetadata;
}

interface CuratedRuleCondition {
  event_type: string;
  process_name?: string;
  parent_process?: string;
  command_line?: string;
  file_path?: string;
  network_destination?: string;
  user?: string;
}

interface CuratedRuleDefinition {
  id: string;
  name: string;
  description: string;
  severity: string;
  tags: string[];
  condition: CuratedRuleCondition;
  action?: 'alert' | 'block' | 'quarantine';
}

interface NamespaceConfig {
  indexName: string;
  sourceName: ProtectionRuleSource;
  sourceDisplayName: string;
  feed: string;
  feedUrl: string;
  upstreamTotalRules: number;
  upstreamCandidateRules?: number;
  license?: LicenseMetadata;
  bundleStateFile: string;
  bundleCachePrefix: string;
}

const CONDITION_FIELD_ORDER: Array<keyof CuratedRuleCondition> = [
  'event_type',
  'process_name',
  'parent_process',
  'command_line',
  'file_path',
  'network_destination',
  'user'
];

const CONFIG_BY_NAMESPACE: Record<ProtectionNamespace, NamespaceConfig> = {
  memory: {
    indexName: '.xdr-defense-memory',
    sourceName: 'capa-curated',
    sourceDisplayName: 'capa',
    feed: 'capa-rules',
    feedUrl: 'https://github.com/mandiant/capa-rules',
    upstreamTotalRules: 1045,
    upstreamCandidateRules: 44,
    license: { name: 'Apache-2.0', url: 'https://github.com/mandiant/capa-rules/blob/master/LICENSE.txt' },
    bundleStateFile: resolvePluginDataPath('registries', 'memory_bundle_states.json'),
    bundleCachePrefix: 'memory_bundle_cache'
  },
  ransomware: {
    indexName: '.xdr-defense-ransomware',
    sourceName: 'falcosecurity-curated',
    sourceDisplayName: 'FalcoSecurity + Aqua Security (Tracee)',
    feed: 'falcosecurity-rules',
    feedUrl: 'https://github.com/falcosecurity/rules',
    upstreamTotalRules: 40,
    license: { name: 'Apache-2.0', url: 'https://github.com/falcosecurity/rules/blob/main/LICENSE' },
    bundleStateFile: resolvePluginDataPath('registries', 'ransomware_bundle_states.json'),
    bundleCachePrefix: 'ransomware_bundle_cache'
  }
};

function nowIso(): string {
  return new Date().toISOString();
}

function namespaceConfig(namespace: ProtectionNamespace): NamespaceConfig {
  return CONFIG_BY_NAMESPACE[namespace];
}

export function getProtectionIndexName(namespace: ProtectionNamespace): string {
  return namespaceConfig(namespace).indexName;
}

export function getProtectionSourceDisplayName(namespace: ProtectionNamespace): string {
  return namespaceConfig(namespace).sourceDisplayName;
}

export function getProtectionCatalogStats(namespace: ProtectionNamespace): {
  source_name: string;
  upstream_total_rules: number;
  upstream_candidate_rules?: number;
} {
  const config = namespaceConfig(namespace);
  return {
    source_name: config.sourceDisplayName,
    upstream_total_rules: config.upstreamTotalRules,
    upstream_candidate_rules: config.upstreamCandidateRules
  };
}

function defaultBundleStateFile(): PersistedBundleStateFile {
  return { version: 1, bundleStates: {} };
}

function cloneValidation(validation: ProtectionRuleValidation): ProtectionRuleValidation {
  return {
    ...validation,
    errors: [...validation.errors],
    warnings: [...validation.warnings]
  };
}

function normalizeValidation(input: unknown): ProtectionRuleValidation {
  if (!input || typeof input !== 'object') {
    return { status: 'valid', errors: [], warnings: [], checkedAt: nowIso() };
  }

  const value = input as Record<string, unknown>;
  return {
    status: value.status === 'invalid' ? 'invalid' : 'valid',
    errors: Array.isArray(value.errors) ? value.errors.map((entry) => String(entry)) : [],
    warnings: Array.isArray(value.warnings) ? value.warnings.map((entry) => String(entry)) : [],
    checkedAt: String(value.checkedAt ?? nowIso())
  };
}

function normalizeTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) {
    return [];
  }
  return tags
    .map((entry) => String(entry).trim())
    .filter((entry) => entry.length > 0)
    .slice(0, 32);
}

function sanitizeSeverity(raw: unknown): string {
  const value = String(raw ?? 'medium').trim().toLowerCase();
  if (value === 'low' || value === 'medium' || value === 'high' || value === 'critical') {
    return value;
  }
  return 'medium';
}

function sanitizeRuleName(namespace: ProtectionNamespace, raw: unknown): string {
  const candidate = String(raw ?? '').trim();
  if (candidate) {
    return candidate.slice(0, 160);
  }
  return `${namespace}_rule_${Date.now()}`;
}

function toRecord(namespace: ProtectionNamespace, id: string, source: any): ProtectionRuleRecord | null {
  if (!id || !source) {
    return null;
  }

  const sourceMetadata = source.source_metadata && typeof source.source_metadata === 'object'
    ? {
        provider: String((source.source_metadata as any).provider ?? ''),
        feed: String((source.source_metadata as any).feed ?? ''),
        upstream_url: String((source.source_metadata as any).upstream_url ?? ''),
        upstream_id: String((source.source_metadata as any).upstream_id ?? ''),
        synced_at: String((source.source_metadata as any).synced_at ?? nowIso())
      }
    : undefined;

  const licenseMetadata = source.license_metadata && typeof source.license_metadata === 'object'
    ? {
        name: (source.license_metadata as any).name ? String((source.license_metadata as any).name) : undefined,
        url: (source.license_metadata as any).url ? String((source.license_metadata as any).url) : undefined
      }
    : undefined;

  return {
    id,
    name: sanitizeRuleName(namespace, source.name),
    source: String(source.source ?? 'custom') as ProtectionRuleSource,
    enabled: Boolean(source.enabled),
    severity: sanitizeSeverity(source.severity),
    tags: normalizeTags(source.tags),
    content: String(source.content ?? ''),
    updatedAt: String(source.updated_at ?? nowIso()),
    validation: normalizeValidation(source.validation),
    source_metadata: sourceMetadata,
    license_metadata: licenseMetadata
  };
}

function toSummary(record: ProtectionRuleRecord): ProtectionRuleSummary {
  return {
    id: record.id,
    name: record.name,
    source: record.source,
    enabled: record.enabled,
    severity: record.severity,
    tags: [...record.tags],
    updatedAt: record.updatedAt,
    validation: cloneValidation(record.validation),
    source_metadata: record.source_metadata ? { ...record.source_metadata } : undefined,
    license_metadata: record.license_metadata ? { ...record.license_metadata } : undefined
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

function isAlreadyExistsError(err: unknown): boolean {
  const msg = String((err as any)?.message ?? err ?? '').toLowerCase();
  return msg.includes('resource_already_exists_exception') || msg.includes('already exists');
}

function indexDefinition() {
  return {
    mappings: {
      properties: {
        name: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
        source: { type: 'keyword' },
        enabled: { type: 'boolean' },
        severity: { type: 'keyword' },
        tags: { type: 'keyword' },
        content: { type: 'text' },
        updated_at: { type: 'date' },
        validation: {
          properties: {
            status: { type: 'keyword' },
            errors: { type: 'text' },
            warnings: { type: 'text' },
            checkedAt: { type: 'date' }
          }
        },
        source_metadata: {
          properties: {
            provider: { type: 'keyword' },
            feed: { type: 'keyword' },
            upstream_url: { type: 'keyword' },
            upstream_id: { type: 'keyword' },
            synced_at: { type: 'date' }
          }
        },
        license_metadata: {
          properties: {
            name: { type: 'keyword' },
            url: { type: 'keyword' }
          }
        }
      }
    }
  };
}

export async function ensureProtectionIndex(client: any, namespace: ProtectionNamespace): Promise<void> {
  const config = namespaceConfig(namespace);
  const existsResponse = await client.indices.exists({ index: config.indexName });
  if (indexExistsResponseToBoolean(existsResponse)) {
    return;
  }

  try {
    await client.indices.create({ index: config.indexName, body: indexDefinition() });
  } catch (err: any) {
    if (!isAlreadyExistsError(err)) {
      throw err;
    }
  }
}

export function validateProtectionRuleContent(contentRaw: unknown): ProtectionRuleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const content = String(contentRaw ?? '');
  const trimmed = content.trim();

  if (trimmed.length === 0) {
    errors.push('Rule content cannot be empty.');
  }
  if (content.length > 200000) {
    errors.push('Rule content exceeds maximum size (200000 bytes).');
  }
  if (trimmed.length > 0 && !/^rules\s*:/m.test(trimmed)) {
    errors.push('Rule content must be a YAML document with a top-level rules: key.');
  }
  if (trimmed.length > 0 && /^rules\s*:/m.test(trimmed)) {
    if (!/^\s*-\s+id\s*:/m.test(trimmed)) {
      errors.push('Rule content must include at least one rule id.');
    }
    if (!/^\s*event_type\s*:/m.test(trimmed)) {
      errors.push('Rule content must include condition.event_type.');
    }
  }

  return {
    status: errors.length > 0 ? 'invalid' : 'valid',
    errors,
    warnings,
    checkedAt: nowIso()
  };
}

async function getRecord(client: any, namespace: ProtectionNamespace, id: string): Promise<ProtectionRuleRecord | null> {
  const config = namespaceConfig(namespace);
  await ensureProtectionIndex(client, namespace);
  try {
    const response = await client.get({ index: config.indexName, id });
    return toRecord(namespace, id, response?.body?._source ?? response?._source);
  } catch (_err) {
    return null;
  }
}

async function saveRecord(client: any, namespace: ProtectionNamespace, record: ProtectionRuleRecord): Promise<void> {
  const config = namespaceConfig(namespace);
  await ensureProtectionIndex(client, namespace);

  const doc: ProtectionIndexDocument = {
    name: record.name,
    source: record.source,
    enabled: record.enabled,
    severity: record.severity,
    tags: [...record.tags],
    content: record.content,
    updated_at: record.updatedAt,
    validation: cloneValidation(record.validation),
    source_metadata: record.source_metadata ? { ...record.source_metadata } : undefined,
    license_metadata: record.license_metadata ? { ...record.license_metadata } : undefined
  };

  await client.update({
    index: config.indexName,
    id: record.id,
    refresh: 'wait_for',
    body: {
      doc,
      doc_as_upsert: true
    }
  });
}

function escapedWildcard(raw: string): string {
  return raw.replace(/[\\*?]/g, '').trim().toLowerCase();
}

export async function listProtectionRules(
  client: any,
  namespace: ProtectionNamespace,
  input?: { page?: number; pageSize?: number; q?: string }
): Promise<ProtectionListResponse> {
  const config = namespaceConfig(namespace);
  await ensureProtectionIndex(client, namespace);

  const page = Math.max(1, Math.floor(Number(input?.page ?? 1) || 1));
  const pageSize = Math.max(1, Math.min(500, Math.floor(Number(input?.pageSize ?? 50) || 50)));
  const from = (page - 1) * pageSize;
  const q = String(input?.q ?? '').trim();

  let query: Record<string, unknown> = { match_all: {} };
  if (q) {
    const escaped = escapedWildcard(q);
    query = {
      bool: {
        should: [
          { wildcard: { 'name.keyword': `*${escaped}*` } },
          { wildcard: { 'source.keyword': `*${escaped}*` } },
          { wildcard: { tags: `*${escaped}*` } }
        ],
        minimum_should_match: 1
      }
    };
  }

  const response = await client.search({
    index: config.indexName,
    from,
    size: pageSize,
    body: {
      query,
      sort: [{ updated_at: { order: 'desc' } }]
    }
  });

  const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
  const totalRaw = response?.body?.hits?.total;
  const total = typeof totalRaw?.value === 'number' ? totalRaw.value : typeof totalRaw === 'number' ? totalRaw : hits.length;

  const rules = hits
    .map((hit: any) => toRecord(namespace, String(hit?._id ?? ''), hit?._source))
    .filter((record: ProtectionRuleRecord | null): record is ProtectionRuleRecord => record !== null)
    .map((record: ProtectionRuleRecord) => toSummary(record));

  return { rules, page, pageSize, total };
}

export async function addCustomProtectionRule(
  client: any,
  namespace: ProtectionNamespace,
  input: { name: unknown; content: unknown; severity?: unknown; tags?: unknown; enabled?: unknown }
): Promise<ProtectionRuleRecord> {
  const validation = validateProtectionRuleContent(input.content);
  const record: ProtectionRuleRecord = {
    id: `${namespace}-custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: sanitizeRuleName(namespace, input.name),
    source: 'custom',
    enabled: validation.status === 'valid' ? (input.enabled !== undefined ? Boolean(input.enabled) : true) : false,
    severity: sanitizeSeverity(input.severity),
    tags: normalizeTags(input.tags),
    content: String(input.content ?? ''),
    updatedAt: nowIso(),
    validation
  };

  await saveRecord(client, namespace, record);
  return record;
}

export async function updateProtectionRule(
  client: any,
  namespace: ProtectionNamespace,
  id: string,
  patch: { enabled?: unknown; content?: unknown; severity?: unknown; tags?: unknown; name?: unknown }
): Promise<{ updated: ProtectionRuleRecord | null; error?: string }> {
  const existing = await getRecord(client, namespace, id);
  if (!existing) {
    return { updated: null, error: 'Rule not found.' };
  }

  const next: ProtectionRuleRecord = {
    ...existing,
    name: patch.name !== undefined ? sanitizeRuleName(namespace, patch.name) : existing.name,
    content: patch.content !== undefined ? String(patch.content) : existing.content,
    severity: patch.severity !== undefined ? sanitizeSeverity(patch.severity) : existing.severity,
    tags: patch.tags !== undefined ? normalizeTags(patch.tags) : existing.tags,
    enabled: patch.enabled !== undefined ? Boolean(patch.enabled) : existing.enabled,
    updatedAt: nowIso(),
    validation: existing.validation
  };

  next.validation = validateProtectionRuleContent(next.content);
  if (next.validation.status === 'invalid') {
    next.enabled = false;
  }

  await saveRecord(client, namespace, next);
  return { updated: next };
}

export async function deleteProtectionRule(
  client: any,
  namespace: ProtectionNamespace,
  id: string
): Promise<{ deleted: boolean; error?: string }> {
  const config = namespaceConfig(namespace);
  await ensureProtectionIndex(client, namespace);
  try {
    await client.delete({ index: config.indexName, id, refresh: 'wait_for' });
    return { deleted: true };
  } catch (_err) {
    return { deleted: false, error: 'Rule not found.' };
  }
}

function renderCuratedRuleContent(definition: CuratedRuleDefinition): string {
  const lines = [
    'rules:',
    `  - id: ${definition.id}`,
    `    name: ${JSON.stringify(definition.name)}`,
    `    description: ${JSON.stringify(definition.description)}`,
    `    severity: ${definition.severity}`,
    '    condition:'
  ];

  for (const field of CONDITION_FIELD_ORDER) {
    const value = definition.condition[field];
    if (!value) {
      continue;
    }
    lines.push(`      ${field}: ${JSON.stringify(value)}`);
  }

  lines.push(`    action: ${definition.action ?? 'alert'}`);
  lines.push('    enabled: true');
  lines.push(`    tags: [${definition.tags.map((tag) => JSON.stringify(tag)).join(', ')}]`);
  return `${lines.join('\n')}\n`;
}

function toCuratedInput(namespace: ProtectionNamespace, definition: CuratedRuleDefinition): CuratedRuleInput {
  const config = namespaceConfig(namespace);
  return {
    id: definition.id,
    name: definition.name,
    severity: definition.severity,
    tags: definition.tags,
    content: renderCuratedRuleContent(definition),
    source_metadata: {
      provider: namespace === 'memory' ? 'mandiant' : 'falcosecurity',
      feed: config.feed,
      upstream_url: config.feedUrl,
      upstream_id: definition.id,
      synced_at: nowIso()
    },
    license_metadata: config.license
  };
}

function curatedMemoryRules(): CuratedRuleInput[] {
  const definitions: CuratedRuleDefinition[] = [
    {
      id: 'capa-memory-memfd-create',
      name: 'memfd-backed execution indicator',
      description: 'Command line suggests memfd-backed payload creation or execution.',
      severity: 'high',
      tags: ['memory', 'capa', 'fileless'],
      condition: { event_type: 'process.start', command_line: '.*(memfd_create|memfd:|fexecve|execveat).*' }
    },
    {
      id: 'capa-memory-dev-shm-exec',
      name: 'Execution from /dev/shm',
      description: 'Executable path points at shared memory staging commonly used by fileless loaders.',
      severity: 'high',
      tags: ['memory', 'capa', 'fileless'],
      condition: { event_type: 'process.start', file_path: '.*/dev/shm/.*' }
    },
    {
      id: 'capa-memory-ptrace-write',
      name: 'Ptrace memory tampering command',
      description: 'Process start indicates ptrace usage associated with memory injection.',
      severity: 'high',
      tags: ['memory', 'capa', 'injection'],
      condition: { event_type: 'process.start', command_line: '.*ptrace.*' }
    },
    {
      id: 'capa-memory-proc-mem-write',
      name: 'Direct /proc memory access',
      description: 'Command line references /proc/<pid>/mem style direct memory writes.',
      severity: 'critical',
      tags: ['memory', 'capa', 'injection'],
      condition: { event_type: 'process.start', command_line: '.*/proc/[0-9]+/mem.*' }
    },
    {
      id: 'capa-memory-process-vm-writev',
      name: 'process_vm_writev indicator',
      description: 'Command line references process_vm_writev-style cross-process memory writes.',
      severity: 'critical',
      tags: ['memory', 'capa', 'injection'],
      condition: { event_type: 'process.start', command_line: '.*process_vm_writev.*' }
    },
    {
      id: 'capa-memory-preload-env',
      name: 'LD_PRELOAD injection indicator',
      description: 'Command line exposes LD_PRELOAD usage that can force-load attacker-controlled libraries.',
      severity: 'high',
      tags: ['memory', 'capa', 'preload'],
      condition: { event_type: 'process.start', command_line: '.*LD_PRELOAD=.*' }
    },
    {
      id: 'capa-memory-preload-file-create',
      name: 'ld.so preload file creation',
      description: 'Creation of /etc/ld.so.preload is a strong library hijack signal.',
      severity: 'critical',
      tags: ['memory', 'capa', 'preload'],
      condition: { event_type: 'file.create', file_path: '/etc/ld\\.so\\.preload' }
    },
    {
      id: 'capa-memory-preload-file-modify',
      name: 'ld.so preload file modification',
      description: 'Modification of /etc/ld.so.preload is a strong library hijack signal.',
      severity: 'critical',
      tags: ['memory', 'capa', 'preload'],
      condition: { event_type: 'file.modify', file_path: '/etc/ld\\.so\\.preload' }
    },
    {
      id: 'capa-memory-shellcode-loader',
      name: 'Shellcode loader command sequence',
      description: 'Command line suggests shellcode decoding followed by direct execution.',
      severity: 'high',
      tags: ['memory', 'capa', 'shellcode'],
      condition: { event_type: 'process.start', command_line: '.*(base64 -d|xxd -r -p|printf [\\\\]x|python -c).*' }
    },
    {
      id: 'capa-memory-anon-exec-mprotect',
      name: 'Anonymous executable mapping tools',
      description: 'Command line suggests mmap or mprotect patterns used by in-memory loaders.',
      severity: 'high',
      tags: ['memory', 'capa', 'rwx'],
      condition: { event_type: 'process.start', command_line: '.*(mprotect|mmap|PROT_EXEC|PROT_WRITE\\|PROT_EXEC).*' }
    },
    {
      id: 'capa-memory-dlopen-temp-so',
      name: 'Temp shared object load indicator',
      description: 'Command line suggests dlopen of a temporary or shared-memory staged library.',
      severity: 'high',
      tags: ['memory', 'capa', 'dlopen'],
      condition: { event_type: 'process.start', command_line: '.*(dlopen|dlmopen).*(/tmp|/dev/shm).*\\.so.*' }
    },
    {
      id: 'capa-memory-deleted-exe',
      name: 'Deleted executable still running',
      description: 'Executable path indicates a deleted on-disk image often seen with hollowing or fileless staging.',
      severity: 'high',
      tags: ['memory', 'capa', 'hollowing'],
      condition: { event_type: 'process.start', file_path: '.* \\(deleted\\)$' }
    },
    {
      id: 'capa-memory-gdb-attach-write',
      name: 'Debugger attach with memory write semantics',
      description: 'Debugger-style command line references attach and memory-write semantics.',
      severity: 'medium',
      tags: ['memory', 'capa', 'debugger'],
      condition: { event_type: 'process.start', command_line: '.*(gdb|lldb).*(attach|set \\{char|dump memory).*' }
    },
    {
      id: 'capa-memory-proc-map-scan',
      name: 'Process maps and memory scan command',
      description: 'Command line indicates active inspection of process maps or memory segments.',
      severity: 'medium',
      tags: ['memory', 'capa', 'recon'],
      condition: { event_type: 'process.start', command_line: '.*(/proc/[0-9]+/maps|pmap |gcore ).*' }
    },
    // namespace and container isolation abuse
    {
      id: 'capa-memory-nsenter-ns',
      name: 'Namespace Entry via nsenter',
      description: 'nsenter used to enter another process namespace, enabling container escape or process injection context.',
      severity: 'high',
      tags: ['memory', 'capa', 'namespace'],
      condition: { event_type: 'process.start', process_name: '^nsenter$' }
    },
    {
      id: 'capa-memory-unshare-user',
      name: 'User Namespace Creation via unshare',
      description: 'unshare creating a user namespace enables unprivileged privilege escalation or isolation bypass.',
      severity: 'medium',
      tags: ['memory', 'capa', 'namespace'],
      condition: { event_type: 'process.start', command_line: '.*unshare.*(--user|-U).*' }
    },
    {
      id: 'capa-memory-unshare-mount',
      name: 'Mount Namespace Separation via unshare',
      description: 'unshare with a mount namespace flag is used to hide mounts or stage fileless execution environments.',
      severity: 'medium',
      tags: ['memory', 'capa', 'namespace'],
      condition: { event_type: 'process.start', command_line: '.*unshare.*(--mount|-m).*' }
    },
    {
      id: 'capa-memory-chroot-tmp',
      name: 'chroot to Temporary or Device Directory',
      description: 'chroot targeting /tmp, /dev, or /run indicates container escape staging or fileless payload isolation.',
      severity: 'high',
      tags: ['memory', 'capa', 'namespace'],
      condition: { event_type: 'process.start', command_line: '.*chroot\\s+(/tmp|/dev|/run).*' }
    },
    // kernel module loading
    {
      id: 'capa-memory-insmod-tmp',
      name: 'Kernel Module Loaded from Temp Directory',
      description: 'insmod loading a kernel module from /tmp or /dev/shm suggests staging for unsigned rootkit payloads.',
      severity: 'critical',
      tags: ['memory', 'capa', 'rootkit'],
      condition: { event_type: 'process.start', process_name: '^insmod$', command_line: '.*(tmp|dev/shm|run/shm).*\\.ko.*' }
    },
    {
      id: 'capa-memory-modprobe-force',
      name: 'Kernel Module Forced Load',
      description: 'modprobe --force bypasses module signature verification, enabling rootkits on locked-down kernels.',
      severity: 'critical',
      tags: ['memory', 'capa', 'rootkit'],
      condition: { event_type: 'process.start', command_line: '.*modprobe.*(--force|-f).*' }
    },
    {
      id: 'capa-memory-rmmod-security',
      name: 'Security or Audit Module Removal',
      description: 'rmmod targeting security, audit, or integrity modules is a precursor to covering memory injection tracks.',
      severity: 'high',
      tags: ['memory', 'capa', 'rootkit'],
      condition: { event_type: 'process.start', command_line: '.*rmmod.*(selinux|apparmor|auditd|integrity|ima).*' }
    },
    // sensitive /proc reads for recon
    {
      id: 'capa-memory-proc-kallsyms',
      name: 'Kernel Symbol Table Read',
      description: '/proc/kallsyms access reveals kernel function addresses used to calculate offsets for kernel exploits.',
      severity: 'high',
      tags: ['memory', 'capa', 'kernel-recon'],
      condition: { event_type: 'file.modify', file_path: '/proc/kallsyms' }
    },
    {
      id: 'capa-memory-proc-kcore',
      name: 'Raw Kernel Memory Image Access',
      description: '/proc/kcore provides raw kernel memory as an ELF core image, used for kernel symbol extraction and exploit development.',
      severity: 'critical',
      tags: ['memory', 'capa', 'kernel-recon'],
      condition: { event_type: 'process.start', command_line: '.*/proc/kcore.*' }
    },
    {
      id: 'capa-memory-proc-syscall-read',
      name: 'Process Syscall State Read',
      description: 'Reading /proc/<pid>/syscall exposes in-flight system call context used to probe process state for injection timing.',
      severity: 'medium',
      tags: ['memory', 'capa', 'kernel-recon'],
      condition: { event_type: 'process.start', command_line: '.*/proc/[0-9]+/syscall.*' }
    },
    {
      id: 'capa-memory-proc-fd-exec',
      name: 'Execution via /proc File Descriptor',
      description: '/proc/self/fd or /proc/<pid>/fd paths used as execution targets run memfd-backed payloads without a real on-disk path.',
      severity: 'high',
      tags: ['memory', 'capa', 'fileless'],
      condition: { event_type: 'process.start', file_path: '.*/proc/(self|[0-9]+)/fd/.*' }
    },
    {
      id: 'capa-memory-run-shm-exec',
      name: 'Execution from /run/shm',
      description: '/run/shm is a POSIX shared memory staging location used by fileless loaders alongside /dev/shm.',
      severity: 'high',
      tags: ['memory', 'capa', 'fileless'],
      condition: { event_type: 'process.start', file_path: '.*/run/shm/.*' }
    },
    // interpreter-based injection
    {
      id: 'capa-memory-python-ctypes',
      name: 'Python ctypes Memory Injection Pattern',
      description: 'Python command-line with ctypes mmap or mprotect usage, a common fileless injection loader pattern.',
      severity: 'high',
      tags: ['memory', 'capa', 'interpreter'],
      condition: { event_type: 'process.start', command_line: '.*(python|python3).*(ctypes|mprotect|PROT_EXEC|mmap).*' }
    },
    {
      id: 'capa-memory-python-cffi',
      name: 'Python cffi Shared Library Injection',
      description: 'Python cffi dlopen or CDLL patterns load in-memory shared objects without disk artifacts.',
      severity: 'high',
      tags: ['memory', 'capa', 'interpreter'],
      condition: { event_type: 'process.start', command_line: '.*(python|python3).*(cffi|CDLL|cdll|ffi\\.dlopen).*' }
    },
    {
      id: 'capa-memory-perl-syscall',
      name: 'Perl Syscall-Based Injection',
      description: 'Perl commands using syscall() to invoke mmap or ptrace-style operations, enabling in-memory code execution.',
      severity: 'high',
      tags: ['memory', 'capa', 'interpreter'],
      condition: { event_type: 'process.start', command_line: '.*perl.*(syscall|mmap|exec\\s*\\().*' }
    },
    {
      id: 'capa-memory-bash-devtcp',
      name: 'Bash /dev/tcp Reverse Shell',
      description: 'Bash /dev/tcp or /dev/udp pseudo-device usage for shell-back connections without external tooling.',
      severity: 'high',
      tags: ['memory', 'capa', 'shell'],
      condition: { event_type: 'process.start', command_line: '.*/dev/(tcp|udp)/.*' }
    },
    // binary patching and ELF tampering
    {
      id: 'capa-memory-patchelf',
      name: 'ELF Binary Patcher Execution',
      description: 'patchelf modifies ELF interpreter or RPATH to redirect library resolution, loading attacker-controlled libraries.',
      severity: 'high',
      tags: ['memory', 'capa', 'elf-tamper'],
      condition: { event_type: 'process.start', process_name: '^patchelf$' }
    },
    {
      id: 'capa-memory-objcopy-binary',
      name: 'Binary Rewrite via objcopy',
      description: 'objcopy replacing or injecting sections in a running executable, a technique for binary patching and code injection.',
      severity: 'high',
      tags: ['memory', 'capa', 'elf-tamper'],
      condition: { event_type: 'process.start', process_name: '^objcopy$', command_line: '.*(--add-section|--update-section|--inject).*' }
    },
    // privilege manipulation
    {
      id: 'capa-memory-setcap',
      name: 'Capability Set on File',
      description: 'setcap granting Linux capabilities directly to a file enables privilege escalation without SUID.',
      severity: 'high',
      tags: ['memory', 'capa', 'privilege'],
      condition: { event_type: 'process.start', process_name: '^setcap$' }
    },
    {
      id: 'capa-memory-capsh',
      name: 'Capability Shell Manipulation',
      description: 'capsh spawn or ambient capability manipulation, used to elevate process privileges programmatically.',
      severity: 'medium',
      tags: ['memory', 'capa', 'privilege'],
      condition: { event_type: 'process.start', process_name: '^capsh$' }
    },
    {
      id: 'capa-memory-newgrp-escalation',
      name: 'Group Escalation via newgrp',
      description: 'newgrp launches a shell with a different primary group, potentially escalating access to group-restricted resources.',
      severity: 'medium',
      tags: ['memory', 'capa', 'privilege'],
      condition: { event_type: 'process.start', process_name: '^newgrp$' }
    },
    // persistence via config hijacking
    {
      id: 'capa-memory-profile-d-create',
      name: 'Profile.d Script Planted',
      description: 'New script in /etc/profile.d/ is executed for every login shell and is a common post-injection persistence mechanism.',
      severity: 'high',
      tags: ['memory', 'capa', 'persistence'],
      condition: { event_type: 'file.create', file_path: '/etc/profile\\.d/.*' }
    },
    {
      id: 'capa-memory-cron-d-create',
      name: 'Cron Job Planted',
      description: 'New file in /etc/cron.d/ or cron time directories installs scheduled execution for persistence.',
      severity: 'high',
      tags: ['memory', 'capa', 'persistence'],
      condition: { event_type: 'file.create', file_path: '/etc/cron\\.(d|hourly|daily|weekly|monthly)/.*' }
    },
    {
      id: 'capa-memory-sudoers-create',
      name: 'Sudoers Rule Planted',
      description: 'New file in /etc/sudoers.d/ grants elevated privileges, used to guarantee persistent root access after initial compromise.',
      severity: 'critical',
      tags: ['memory', 'capa', 'persistence'],
      condition: { event_type: 'file.create', file_path: '/etc/sudoers\\.d/.*' }
    },
    {
      id: 'capa-memory-bashrc-modify',
      name: 'Shell RC File Modified',
      description: 'Modification of ~/.bashrc, ~/.bash_profile, or ~/.profile injects code that runs on every interactive shell start.',
      severity: 'high',
      tags: ['memory', 'capa', 'persistence'],
      condition: { event_type: 'file.modify', file_path: '.*(bashrc|bash_profile|bash_login|\\.profile)$' }
    },
    // docker and container escape
    {
      id: 'capa-memory-docker-socket',
      name: 'Docker Socket Access',
      description: 'Access to /var/run/docker.sock grants full control over the Docker daemon, enabling container escape to the host.',
      severity: 'critical',
      tags: ['memory', 'capa', 'container-escape'],
      condition: { event_type: 'file.modify', file_path: '/var/run/docker\\.sock' }
    },
    {
      id: 'capa-memory-crictl-exec',
      name: 'Container Runtime CLI Exec',
      description: 'crictl or ctr exec spawning processes inside containers from the host can indicate a container escape attempt.',
      severity: 'high',
      tags: ['memory', 'capa', 'container-escape'],
      condition: { event_type: 'process.start', process_name: '^(crictl|ctr)$', command_line: '.*exec.*' }
    },
    // named pipe tricks
    {
      id: 'capa-memory-mkfifo-tmp',
      name: 'FIFO Created in Temp Directory',
      description: 'mkfifo creating a named pipe in /tmp or /dev/shm is used in staged shellcode delivery without disk artifacts.',
      severity: 'medium',
      tags: ['memory', 'capa', 'fileless'],
      condition: { event_type: 'process.start', process_name: '^mkfifo$', command_line: '.*(tmp|dev/shm).*' }
    },
    // kernel memory manipulation
    {
      id: 'capa-memory-keyctl-inject',
      name: 'Kernel Keyring Injection',
      description: 'keyctl padd or pupdate loading large binary blobs into kernel keyrings is used to stage shellcode in kernel memory.',
      severity: 'high',
      tags: ['memory', 'capa', 'kernel-recon'],
      condition: { event_type: 'process.start', process_name: '^keyctl$', command_line: '.*(padd|pupdate|pinstantiate).*' }
    },
    {
      id: 'capa-memory-core-pattern-modify',
      name: 'Kernel Core Pattern Hijack',
      description: 'Writing to /proc/sys/kernel/core_pattern with a pipe prefix redirects crash dumps to an attacker-controlled binary.',
      severity: 'critical',
      tags: ['memory', 'capa', 'kernel-recon'],
      condition: { event_type: 'file.modify', file_path: '/proc/sys/kernel/core_pattern' }
    }
  ];

  return definitions.map((definition) => toCuratedInput('memory', definition));
}

function curatedRansomwareRules(): CuratedRuleInput[] {
  const definitions: CuratedRuleDefinition[] = [
    {
      id: 'falcosecurity-ransomware-canary-modify',
      name: 'Canary file modified',
      description: 'Modification of an XDR canary file is a strong ransomware indicator.',
      severity: 'critical',
      tags: ['ransomware', 'falcosecurity', 'canary'],
      condition: { event_type: 'file.modify', file_path: '.*\\.xdr-canary$' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-canary-delete',
      name: 'Canary file deleted',
      description: 'Deletion of an XDR canary file is a strong ransomware indicator.',
      severity: 'critical',
      tags: ['ransomware', 'falcosecurity', 'canary'],
      condition: { event_type: 'file.delete', file_path: '.*\\.xdr-canary$' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-shadow-delete',
      name: 'Backup or shadow copy deletion command',
      description: 'Command line attempts to delete backups or recovery points.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'backup-tamper'],
      condition: { event_type: 'process.start', command_line: '.*(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete).*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-boot-recovery-disable',
      name: 'Boot recovery disabled',
      description: 'Boot recovery or boot status policy changes are often used before destructive encryption.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'impact'],
      condition: { event_type: 'process.start', command_line: '.*(bcdedit.*/set.*recoveryenabled.*no|bcdedit.*/set.*bootstatuspolicy.*ignoreallfailures).*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-snapshot-delete',
      name: 'Linux snapshot deletion command',
      description: 'Snapshot deletion may indicate ransomware disabling restoration on Linux hosts.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'snapshot'],
      condition: { event_type: 'process.start', command_line: '.*(btrfs subvolume delete|zfs destroy|lvremove).*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-encryptor-cli',
      name: 'Bulk encryption CLI usage',
      description: 'Encryption utilities launched with flags common in bulk file encryption workflows.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'encryptor'],
      condition: { event_type: 'process.start', command_line: '.*(openssl enc|gpg -c|age -p|7z a -p).*' }
    },
    {
      id: 'falcosecurity-ransomware-note-drop',
      name: 'Ransom note file created',
      description: 'Creation of common ransom note filenames.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'ransom-note'],
      condition: { event_type: 'file.create', file_path: '.*(readme|recover|restore|decrypt|how_to).*\\.(txt|html|hta)$' }
    },
    {
      id: 'falcosecurity-ransomware-encrypted-extension',
      name: 'Suspicious encrypted file extension',
      description: 'Rename to a known ransomware-style extension.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'extension'],
      condition: { event_type: 'file.rename', file_path: '.*\\.(locked|encrypted|crypt|enc|ryuk|conti|clop|akira|blackcat)$' }
    },
    {
      id: 'falcosecurity-ransomware-backup-service-stop',
      name: 'Backup tooling stopped',
      description: 'Command line attempts to stop or kill backup tooling before destructive actions.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'backup-tamper'],
      condition: { event_type: 'process.start', command_line: '.*(systemctl stop .*backup|service .*backup stop|pkill .*backup|killall .*backup).*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-exfil-tooling',
      name: 'Exfiltration tooling before encryption',
      description: 'Data transfer tools launched against user-content paths often used in double extortion.',
      severity: 'medium',
      tags: ['ransomware', 'falcosecurity', 'exfiltration'],
      condition: { event_type: 'process.start', command_line: '.*(rclone|rsync|scp|curl -T).*(/home|/srv|/var/www).*' }
    },
    {
      id: 'falcosecurity-ransomware-chattr-immutable',
      name: 'Immutable Flag Stripped in Bulk',
      description: 'chattr -i stripping immutable flags recursively prepares protected files for encryption.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'filesystem'],
      condition: { event_type: 'process.start', command_line: '.*chattr.*-i.*(tmp|home|srv|var|data).*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-log-delete',
      name: 'Log Directory Mass Deletion',
      description: 'Mass deletion of log files destroys forensic evidence after encryption.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'anti-forensics'],
      condition: { event_type: 'process.start', command_line: '.*find.*/var/log.*-delete.*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-extra-note-patterns',
      name: 'Ransom Instruction File Created',
      description: 'Creation of files matching common instruction or readme ransom note patterns.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'ransom-note'],
      condition: { event_type: 'file.create', file_path: '.*(READ_ME|INSTRUCTIONS|ATTENTION|DECRYPT_FILES|YOUR_FILES|HOW_TO_RESTORE|IMPORTANT).*\\.(txt|html|hta)$' }
    },
    {
      id: 'falcosecurity-ransomware-extra-extensions',
      name: 'Additional Ransomware File Extensions',
      description: 'Rename to extensions associated with ransomware families not covered by the base extension rule.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'extension'],
      condition: { event_type: 'file.rename', file_path: '.*\\.(lockbit|hive|blackmatter|alphv|monti|zeppelin|phobos|sodinokibi|dharma|matrix|xorist|stop|djvu)$' }
    },
    {
      id: 'falcosecurity-ransomware-firewall-disable',
      name: 'Firewall Disabled Before Exfil',
      description: 'Disabling the host firewall before data transfer is a double-extortion staging pattern.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'anti-defense'],
      condition: { event_type: 'process.start', command_line: '.*(iptables -F|ufw disable|firewall-cmd.*--panic-on|systemctl stop.*firewall).*' },
      action: 'block'
    },
    {
      id: 'falcosecurity-ransomware-recovery-partition',
      name: 'Recovery Partition Targeting',
      description: 'Commands targeting recovery or EFI partitions to disable OS recovery before encryption.',
      severity: 'high',
      tags: ['ransomware', 'falcosecurity', 'impact'],
      condition: { event_type: 'process.start', command_line: '.*(parted|fdisk|gdisk|wipefs|dd if=/dev/zero).*(recovery|efi|boot).*' },
      action: 'block'
    }
  ];

  return definitions.map((definition) => toCuratedInput('ransomware', definition));
}

function curatedTraceeRansomwareRules(): CuratedRuleInput[] {
  const definitions: CuratedRuleDefinition[] = [
    {
      id: 'tracee-ransomware-shred-usage',
      name: 'File Shredding Tool Launched',
      description: 'shred securely overwrites file contents, used by ransomware to destroy backups or evidence after encryption.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'destruction'],
      condition: { event_type: 'process.start', process_name: '^shred$' },
      action: 'block'
    },
    {
      id: 'tracee-ransomware-wipe-usage',
      name: 'Wipe Utility Launched',
      description: 'wipe securely removes files, used to destroy data or backups before or after ransomware deployment.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'destruction'],
      condition: { event_type: 'process.start', process_name: '^wipe$' },
      action: 'block'
    },
    {
      id: 'tracee-ransomware-dd-overwrite',
      name: 'dd Overwriting Disk Device',
      description: 'dd writing zeros or random bytes to disk devices, used for destructive wiping before or after encryption.',
      severity: 'critical',
      tags: ['ransomware', 'tracee', 'destruction'],
      condition: { event_type: 'process.start', command_line: '.*dd.*(if=/dev/(zero|urandom)|of=/dev/(sd|vd|xvd|nvme)).*' },
      action: 'block'
    },
    {
      id: 'tracee-ransomware-python-encrypt',
      name: 'Python Encryption One-Liner',
      description: 'Python command-line using Fernet, AES, or cryptography modules for one-shot bulk file encryption.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', command_line: '.*(python|python3).*(Fernet|AES|cryptography|encrypt|cipher).*' }
    },
    {
      id: 'tracee-ransomware-tar-openssl',
      name: 'Tar Archive with Encryption',
      description: 'tar piped through openssl enc or gpg to create encrypted archives, a bulk-encryption staging pattern.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', command_line: '.*tar.*(openssl enc|gpg -c|gpg --symmetric).*' }
    },
    {
      id: 'tracee-ransomware-age-encrypt',
      name: 'age Encryption Tool Used',
      description: 'age is a modern encryption tool increasingly adopted by ransomware campaigns for its simplicity.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', process_name: '^age$', command_line: '.*-e.*' }
    },
    {
      id: 'tracee-ransomware-rage-encrypt',
      name: 'rage Encryption Tool Used',
      description: 'rage (Rust implementation of age) is used in the same ransomware and double-extortion campaigns as age.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', process_name: '^rage$', command_line: '.*-e.*' }
    },
    {
      id: 'tracee-ransomware-gocryptfs-mount',
      name: 'gocryptfs Encrypted Mount',
      description: 'gocryptfs mounts an encrypted FUSE filesystem, used to transparently encrypt user directories without visible extension changes.',
      severity: 'medium',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', process_name: '^gocryptfs$' }
    },
    {
      id: 'tracee-ransomware-encfs-mount',
      name: 'EncFS Encrypted Mount',
      description: 'encfs is a FUSE encryption filesystem used in some ransomware variants to transparently encrypt user directories.',
      severity: 'medium',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', process_name: '^encfs$' }
    },
    {
      id: 'tracee-ransomware-zip-password',
      name: 'Password-Protected Archive over User Data',
      description: '7z, zip, or rar creating password-protected archives over user content, a double-extortion staging pattern.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'exfiltration'],
      condition: { event_type: 'process.start', command_line: '.*(7z a -p|zip -P |rar a -hp|zip.*--password).*(/home|/srv|/var/www|/data).*' }
    },
    {
      id: 'tracee-ransomware-rclone-exfil',
      name: 'Rclone Remote Sync or Copy',
      description: 'rclone sync, copy, or mount commands targeting cloud storage are used in double-extortion pre-encryption data exfiltration.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'exfiltration'],
      condition: { event_type: 'process.start', process_name: '^rclone$', command_line: '.*(copy|sync|move|mount).*' }
    },
    {
      id: 'tracee-ransomware-mega-upload',
      name: 'MEGA Cloud Upload Tool',
      description: 'mega-cmd, megaput, or megacopy used for mass file upload, commonly seen in double-extortion pre-encryption staging.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'exfiltration'],
      condition: { event_type: 'process.start', process_name: '^(mega-cmd|megaput|mega-put|megacopy)$' }
    },
    {
      id: 'tracee-ransomware-journal-vacuum',
      name: 'Journal Log Vacuumed',
      description: 'journalctl --vacuum-size or --vacuum-time destroys systemd journal logs to hinder incident response.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'anti-forensics'],
      condition: { event_type: 'process.start', command_line: '.*journalctl.*(--vacuum-size|--vacuum-time|--rotate).*' }
    },
    {
      id: 'tracee-ransomware-log-truncate',
      name: 'Log File Truncation',
      description: 'truncate -s 0 against /var/log files destroys audit trails as part of ransomware anti-forensics.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'anti-forensics'],
      condition: { event_type: 'process.start', command_line: '.*truncate.*-s.*0.*/var/log.*' }
    },
    {
      id: 'tracee-ransomware-smb-mount',
      name: 'SMB Share Mounted for Lateral Encryption',
      description: 'CIFS/SMB share mounting against internal hosts, used to expand ransomware encryption to network-accessible shares.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'lateral-movement'],
      condition: { event_type: 'process.start', command_line: '.*mount.*(cifs|smb|-t cifs).*' }
    },
    {
      id: 'tracee-ransomware-find-encrypt-loop',
      name: 'Find-Based Batch Encryption Loop',
      description: 'find combined with openssl, gpg, or age for recursive file encryption without a purpose-built binary.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', command_line: '.*find.*(openssl enc|gpg -c|age -e|-exec.*encrypt).*' }
    },
    {
      id: 'tracee-ransomware-hta-note-drop',
      name: 'HTA Ransom Note Dropped',
      description: '.hta files are commonly used in ransomware deployments as browser-displayable ransom note format.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'ransom-note'],
      condition: { event_type: 'file.create', file_path: '.*\\.hta$' }
    },
    {
      id: 'tracee-ransomware-readme-echo',
      name: 'Ransom Note Written via Echo',
      description: 'Shell echo or printf writing ransom-note-style content to disk text files, used in script-based ransomware.',
      severity: 'medium',
      tags: ['ransomware', 'tracee', 'ransom-note'],
      condition: { event_type: 'process.start', command_line: '.*(echo|printf).*(READ|DECRYPT|RECOVER|RESTORE|RANSOM).*\\.(txt|html).*' }
    },
    {
      id: 'tracee-ransomware-tune2fs-nojournal',
      name: 'Ext4 Journal Disabled',
      description: 'tune2fs removing the ext4 journal prevents crash recovery, making encryption irreversible on power loss.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'destruction'],
      condition: { event_type: 'process.start', command_line: '.*tune2fs.*(has_journal|journal_data).*' }
    },
    {
      id: 'tracee-ransomware-rm-userhome',
      name: 'Recursive Deletion of User Data',
      description: 'rm -rf targeting /home, /srv, /var/www, or /data is destructive after encryption in wiper-ransomware variants.',
      severity: 'critical',
      tags: ['ransomware', 'tracee', 'destruction'],
      condition: { event_type: 'process.start', command_line: '.*rm\\s+(-rf|-fr).*(home|srv|var/www|data).*' },
      action: 'block'
    },
    {
      id: 'tracee-ransomware-cron-bulk-disable',
      name: 'Backup and Cron Services Disabled',
      description: 'Batch systemctl stop or disable targeting cron, backup, or timer units to prevent backup execution before encryption.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'anti-defense'],
      condition: { event_type: 'process.start', command_line: '.*systemctl.*(stop|disable).*(cron|anacron|atd|backup|rsync).*' }
    },
    {
      id: 'tracee-ransomware-smbclient-mass-put',
      name: 'SMB Client Mass File Upload',
      description: 'smbclient mput or recurse commands uploading large file sets are used to exfiltrate originals or spread encrypted files.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'lateral-movement'],
      condition: { event_type: 'process.start', process_name: '^smbclient$', command_line: '.*(mput|recurse).*' }
    },
    {
      id: 'tracee-ransomware-gpg-batch-keygen',
      name: 'GPG Batch Key Generation',
      description: 'GPG batch key generation creates asymmetric keys for per-victim key management in sophisticated ransomware.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', command_line: '.*gpg.*(--batch|--gen-key|--full-gen-key).*' }
    },
    {
      id: 'tracee-ransomware-python-walk-encrypt',
      name: 'Python Recursive Filesystem Walk for Encryption',
      description: 'Python os.walk() combined with encryption library calls, the core pattern in Python-based ransomware scripts.',
      severity: 'high',
      tags: ['ransomware', 'tracee', 'encryptor'],
      condition: { event_type: 'process.start', command_line: '.*(python|python3).*(os\\.walk|os\\.listdir).*(encrypt|Fernet|AES|cipher).*' }
    },
    {
      id: 'tracee-ransomware-tor-launch',
      name: 'Tor Client Launch Post-Compromise',
      description: 'Tor client started after filesystem activity, used to communicate with ransomware C2 or confirm payment.',
      severity: 'medium',
      tags: ['ransomware', 'tracee', 'c2'],
      condition: { event_type: 'process.start', process_name: '^(tor|torsocks|torify)$' }
    }
  ];

  return definitions.map((def) => ({
    id: def.id,
    name: def.name,
    severity: def.severity,
    tags: def.tags,
    content: renderCuratedRuleContent(def),
    source: 'tracee-curated' as ProtectionRuleSource,
    source_metadata: {
      provider: 'aquasecurity',
      feed: 'tracee-signatures',
      upstream_url: 'https://github.com/aquasecurity/tracee',
      upstream_id: def.id,
      synced_at: nowIso()
    },
    license_metadata: { name: 'Apache-2.0', url: 'https://github.com/aquasecurity/tracee/blob/main/LICENSE' }
  }));
}

function curatedRules(namespace: ProtectionNamespace): CuratedRuleInput[] {
  if (namespace === 'memory') {
    return curatedMemoryRules();
  }
  return [...curatedRansomwareRules(), ...curatedTraceeRansomwareRules()];
}

function bundleCachePath(namespace: ProtectionNamespace, policyId: string): string {
  const config = namespaceConfig(namespace);
  return resolvePluginDataPath('registries', `${config.bundleCachePrefix}_${encodeURIComponent(policyId)}.json`);
}

export interface BundleRuleEntry {
  id: string;
  filename: string;
  content: string;
  sha256: string;
  enabled: boolean;
  source: string;
  updatedAt: string;
}

function bundleContentDigest(policyId: string, rules: BundleRuleEntry[], activeChecksums: string[]): string {
  return crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        policy_id: policyId,
        rules: rules.map((rule) => ({
          id: rule.id,
          sha256: rule.sha256,
          enabled: rule.enabled,
          source: rule.source,
          updatedAt: rule.updatedAt
        })),
        active_checksums: activeChecksums
      }),
      'utf8'
    )
    .digest('hex');
}

function loadBundleStateFile(namespace: ProtectionNamespace): PersistedBundleStateFile {
  const config = namespaceConfig(namespace);
  return readJsonFile<PersistedBundleStateFile>(config.bundleStateFile, defaultBundleStateFile());
}

function saveBundleStateFile(namespace: ProtectionNamespace, state: PersistedBundleStateFile): void {
  const config = namespaceConfig(namespace);
  writeJsonFile(config.bundleStateFile, state);
}

function buildBundleRuleEntries(records: ProtectionRuleRecord[]): BundleRuleEntry[] {
  return records
    .filter((record) => record.validation.status === 'valid')
    .map((record) => ({
      id: record.id,
      filename: `${record.id}.yml`,
      content: record.content,
      sha256: crypto.createHash('sha256').update(record.content, 'utf8').digest('hex'),
      enabled: record.enabled,
      source: record.source,
      updatedAt: record.updatedAt
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
}

export interface SignedBundleResponse {
  manifest_version: 1;
  policy_id: string;
  bundle_version: number;
  generated_at: string;
  signing_alg: 'ed25519';
  rules: BundleRuleEntry[];
  active_checksums: string[];
  signature_base64: string;
  signed_payload_base64: string;
}

interface BundlePayload {
  manifest_version: 1;
  policy_id: string;
  bundle_version: number;
  generated_at: string;
  signing_alg: 'ed25519';
  rules: BundleRuleEntry[];
  active_checksums: string[];
}

export function getProtectionSigningReadiness(): { ready: boolean; reason?: string } {
  const key = getSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

async function allRecords(client: any, namespace: ProtectionNamespace): Promise<ProtectionRuleRecord[]> {
  const config = namespaceConfig(namespace);
  await ensureProtectionIndex(client, namespace);
  try {
    const response = await client.search({
      index: config.indexName,
      size: 10000,
      body: { query: { match_all: {} } }
    });
    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    return hits
      .map((hit: any) => toRecord(namespace, String(hit?._id ?? ''), hit?._source))
      .filter((record: ProtectionRuleRecord | null): record is ProtectionRuleRecord => record !== null);
  } catch (_err) {
    return [];
  }
}

export async function buildSignedProtectionBundle(
  client: any,
  namespace: ProtectionNamespace,
  policyId: string
): Promise<{ bundle?: SignedBundleResponse; error?: string }> {
  const keyResult = getSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    return { error: keyResult.error ?? 'Signing key is unavailable.' };
  }

  const records = await allRecords(client, namespace);
  const rules = buildBundleRuleEntries(records);
  const activeChecksums = rules.filter((entry) => entry.enabled).map((entry) => entry.sha256).sort((a, b) => a.localeCompare(b));
  const digest = bundleContentDigest(policyId, rules, activeChecksums);

  const stateFile = loadBundleStateFile(namespace);
  const existing = stateFile.bundleStates[policyId];
  const nextState =
    existing && existing.content_digest === digest
      ? existing
      : {
          bundle_version: (existing?.bundle_version ?? 0) + 1,
          generated_at: nowIso(),
          content_digest: digest
        };

  const cachePath = bundleCachePath(namespace, policyId);
  if (existing && existing.content_digest === digest) {
    const cached = readJsonFile<SignedBundleResponse | null>(cachePath, null);
    if (cached && cached.bundle_version === nextState.bundle_version) {
      return { bundle: cached };
    }
  } else {
    stateFile.bundleStates[policyId] = nextState;
    saveBundleStateFile(namespace, stateFile);
  }

  const payload: BundlePayload = {
    manifest_version: 1,
    policy_id: policyId,
    bundle_version: nextState.bundle_version,
    generated_at: nextState.generated_at,
    signing_alg: 'ed25519',
    rules,
    active_checksums: activeChecksums
  };

  const payloadBytes = BufferCtor.from(JSON.stringify(payload), 'utf8');
  const signature = crypto.sign(null, payloadBytes, keyResult.privateKey);

  const bundle: SignedBundleResponse = {
    ...payload,
    signature_base64: signature.toString('base64'),
    signed_payload_base64: payloadBytes.toString('base64')
  };

  writeJsonFile(cachePath, bundle);
  return { bundle };
}

export async function syncProtectionOpenSource(
  client: any,
  namespace: ProtectionNamespace,
  reportProgress?: (step: ProtectionSyncStep) => void
): Promise<ProtectionSyncResult> {
  const config = namespaceConfig(namespace);
  const sources = curatedRules(namespace);
  const steps: ProtectionSyncStep[] = [];

  const sourceLabel = (source: CuratedRuleInput): string => {
    if (source.source === 'tracee-curated' || source.source_metadata?.provider === 'aquasecurity') {
      return 'Aqua Security / Tracee';
    }
    if (source.source === 'falcosecurity-curated' || source.source_metadata?.provider === 'falcosecurity') {
      return 'FalcoSecurity';
    }
    if (source.source === 'capa-curated' || source.source_metadata?.provider === 'mandiant') {
      return 'Mandiant capa';
    }
    return source.source_metadata?.provider ? String(source.source_metadata.provider) : String(source.source ?? config.sourceName);
  };

  const pushStep = (stage: string, message: string, details?: Record<string, unknown>): void => {
    const step: ProtectionSyncStep = {
      stage,
      message,
      at: nowIso(),
      details
    };
    steps.push(step);
    if (typeof reportProgress === 'function') {
      reportProgress(step);
    }
  };

  const breakdownMap = new Map<string, ProtectionSyncSourceBreakdown>();
  for (const source of sources) {
    const label = sourceLabel(source);
    const current = breakdownMap.get(label) ?? { source: label, attempted: 0, imported: 0, unchanged: 0 };
    current.attempted += 1;
    breakdownMap.set(label, current);
  }

  pushStep('queue_start', `${namespace === 'memory' ? 'Memory' : 'Ransomware'} sync queued and starting.`);
  pushStep('prepare_source_list', `Prepared source list with ${sources.length} curated rules for ${config.sourceDisplayName}.`, {
    sources: Array.from(breakdownMap.values()).map((item) => item.source),
    curated_rules: sources.length
  });

  pushStep('validate_transform_start', `Validating and transforming ${sources.length} curated rules.`);

  const transformed: Array<{ record: ProtectionRuleRecord; changed: boolean; sourceKey: string }> = [];
  let validCount = 0;
  let invalidCount = 0;

  for (let idx = 0; idx < sources.length; idx += 1) {
    const source = sources[idx];
    const existing = await getRecord(client, namespace, source.id);
    const validation = validateProtectionRuleContent(source.content);
    const key = sourceLabel(source);
    const record: ProtectionRuleRecord = {
      id: source.id,
      name: source.name,
      source: source.source ?? config.sourceName,
      enabled: validation.status === 'valid' ? existing?.enabled ?? true : false,
      severity: sanitizeSeverity(source.severity),
      tags: normalizeTags(source.tags),
      content: source.content,
      updatedAt: nowIso(),
      validation,
      source_metadata: source.source_metadata,
      license_metadata: source.license_metadata ?? config.license
    };

    const changed =
      !existing ||
      existing.name !== record.name ||
      existing.content !== record.content ||
      existing.enabled !== record.enabled ||
      existing.severity !== record.severity ||
      JSON.stringify(existing.tags) !== JSON.stringify(record.tags) ||
      existing.validation.status !== record.validation.status;

    transformed.push({ record, changed, sourceKey: key });
    if (record.validation.status === 'valid') {
      validCount += 1;
    } else {
      invalidCount += 1;
    }

    if ((idx + 1) % 25 === 0 || idx + 1 === sources.length) {
      pushStep('validate_transform_progress', `Validated and transformed ${idx + 1}/${sources.length} rules.`);
    }
  }

  pushStep('validate_transform_complete', `Validation complete: ${validCount} valid, ${invalidCount} invalid.`);

  const importedBySource = new Map<string, number>();
  const unchangedBySource = new Map<string, number>();
  const changedEntries = transformed.filter((entry) => entry.changed);

  pushStep('upsert_batch_start', `Preparing to upsert ${changedEntries.length} changed rules to ${config.indexName}.`);

  let imported = 0;
  let unchanged = 0;

  for (let idx = 0; idx < transformed.length; idx += 1) {
    const entry = transformed[idx];
    if (entry.changed) {
      await saveRecord(client, namespace, entry.record);
      imported += 1;
      importedBySource.set(entry.sourceKey, (importedBySource.get(entry.sourceKey) ?? 0) + 1);
    } else {
      unchanged += 1;
      unchangedBySource.set(entry.sourceKey, (unchangedBySource.get(entry.sourceKey) ?? 0) + 1);
    }

    if ((idx + 1) % 25 === 0 || idx + 1 === transformed.length) {
      pushStep('upsert_batch_progress', `Applied ${idx + 1}/${transformed.length} rule updates.`, {
        imported,
        unchanged
      });
    }
  }

  for (const item of Array.from(breakdownMap.values())) {
    item.imported = importedBySource.get(item.source) ?? 0;
    item.unchanged = unchangedBySource.get(item.source) ?? 0;
    pushStep('source_summary', `${item.source}: imported ${item.imported}, unchanged ${item.unchanged}, attempted ${item.attempted}.`);
  }

  pushStep('finalize_refresh', `Refreshing index ${config.indexName} visibility.`);
  await client.indices.refresh({ index: config.indexName });

  pushStep('complete', `Sync completed for ${config.sourceDisplayName}. Imported ${imported}, unchanged ${unchanged}.`);

  const sourceBreakdown = Array.from(breakdownMap.values());

  return {
    imported,
    unchanged,
    attempted: sources.length,
    source: config.feedUrl,
    source_name: config.sourceDisplayName,
    index_name: config.indexName,
    upstream_total_rules: config.upstreamTotalRules,
    upstream_candidate_rules: config.upstreamCandidateRules,
    curated_rules: sources.length,
    steps,
    source_breakdown: sourceBreakdown
  };
}
