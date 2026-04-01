declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';
import { getSigningPrivateKey } from './signing_keys';

export const YARA_INDEX_NAME = '.xdr-defense-yara';

export type YaraRuleSource = 'custom' | 'forge-core';
export type YaraValidationStatus = 'valid' | 'invalid';

export interface YaraRuleValidation {
  status: YaraValidationStatus;
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

export interface YaraIndexDocument {
  name: string;
  source: YaraRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  updated_at: string;
  validation: YaraRuleValidation;
}

export interface YaraRuleRecord {
  id: string;
  name: string;
  source: YaraRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  updatedAt: string;
  validation: YaraRuleValidation;
}

export interface YaraRuleSummary {
  id: string;
  name: string;
  source: YaraRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  updatedAt: string;
  validation: YaraRuleValidation;
}

export interface BundleRuleEntry {
  id: string;
  filename: string;
  content: string;
  sha256: string;
  enabled: boolean;
  source: YaraRuleSource;
  updatedAt: string;
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

interface PersistedBundleState {
  bundle_version: number;
  generated_at: string;
  content_digest: string;
}

interface PersistedBundleStateFile {
  version: 1;
  bundleStates: Record<string, PersistedBundleState>;
}

const BUNDLE_STATE_FILE = resolvePluginDataPath('registries', 'yara_bundle_states.json');

let yaraIndexReady = false;
let yaraIndexEnsureInFlight: Promise<void> | null = null;

function nowIso(): string {
  return new Date().toISOString();
}

function defaultBundleStateFile(): PersistedBundleStateFile {
  return {
    version: 1,
    bundleStates: {}
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

function sanitizeRuleName(raw: unknown): string {
  const candidate = String(raw ?? '').trim();
  if (!candidate) {
    return `custom_rule_${Date.now()}`;
  }
  return candidate.slice(0, 160);
}

function cloneValidation(validation: YaraRuleValidation): YaraRuleValidation {
  return {
    ...validation,
    errors: [...validation.errors],
    warnings: [...validation.warnings]
  };
}

function normalizeValidation(input: unknown): YaraRuleValidation {
  if (!input || typeof input !== 'object') {
    return {
      status: 'valid',
      errors: [],
      warnings: [],
      checkedAt: nowIso()
    };
  }

  const value = input as Record<string, unknown>;
  return {
    status: value.status === 'invalid' ? 'invalid' : 'valid',
    errors: Array.isArray(value.errors) ? value.errors.map((entry) => String(entry)) : [],
    warnings: Array.isArray(value.warnings) ? value.warnings.map((entry) => String(entry)) : [],
    checkedAt: String(value.checkedAt ?? nowIso())
  };
}

export function validateYaraContent(contentRaw: unknown, expectedName?: string): YaraRuleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const content = String(contentRaw ?? '');

  if (content.trim().length === 0) {
    errors.push('Rule content cannot be empty.');
  }
  if (content.length > 200_000) {
    errors.push('Rule content exceeds maximum size (200000 bytes).');
  }

  const ruleNameMatch = content.match(/\brule\s+([A-Za-z0-9_]{1,128})\b/);
  if (!ruleNameMatch) {
    errors.push('Missing valid YARA rule declaration (e.g., rule sample_name).');
  }

  if (expectedName && ruleNameMatch && expectedName.trim().length > 0) {
    const normalizedExpected = expectedName.trim().replace(/\s+/g, '_');
    if (ruleNameMatch[1] !== normalizedExpected) {
      warnings.push(`Rule declaration name (${ruleNameMatch[1]}) does not match provided name (${normalizedExpected}).`);
    }
  }

  if (!/\bcondition\s*:/i.test(content)) {
    errors.push('Missing YARA condition section.');
  }

  let openBraces = 0;
  let inString = false;
  let inBlockComment = false;
  let inLineComment = false;
  let mismatch = false;
  for (let index = 0; index < content.length; index += 1) {
    const ch = content[index];
    const next = index + 1 < content.length ? content[index + 1] : '';
    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
      }
      continue;
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        index += 1;
      }
      continue;
    }
    if (inString) {
      if (ch === '\\') {
        index += 1;
        continue;
      }
      if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '/' && next === '/') {
      inLineComment = true;
      index += 1;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlockComment = true;
      index += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{') {
      openBraces += 1;
      continue;
    }
    if (ch === '}') {
      openBraces -= 1;
      if (openBraces < 0) {
        errors.push('Mismatched braces found in rule content.');
        mismatch = true;
        break;
      }
    }
  }
  if (!mismatch && openBraces !== 0) {
    errors.push('Unbalanced braces in rule content.');
  }

  return {
    status: errors.length > 0 ? 'invalid' : 'valid',
    errors,
    warnings,
    checkedAt: nowIso()
  };
}

function toRecord(id: string, source: any): YaraRuleRecord | null {
  if (!id || !source) {
    return null;
  }

  return {
    id,
    name: sanitizeRuleName(source.name),
    source: String(source.source ?? 'custom') === 'forge-core' ? 'forge-core' : 'custom',
    enabled: Boolean(source.enabled),
    severity: sanitizeSeverity(source.severity),
    tags: normalizeTags(source.tags),
    content: String(source.content ?? ''),
    updatedAt: String(source.updated_at ?? nowIso()),
    validation: normalizeValidation(source.validation)
  };
}

function mapSummaryHit(hit: any): YaraRuleSummary | null {
  const id = String(hit?._id ?? '').trim();
  const record = toRecord(id, hit?._source);
  if (!record) {
    return null;
  }

  return {
    id: record.id,
    name: record.name,
    source: record.source,
    enabled: record.enabled,
    severity: record.severity,
    tags: [...record.tags],
    updatedAt: record.updatedAt,
    validation: cloneValidation(record.validation)
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

function yaraIndexDefinition() {
  return {
    mappings: {
      properties: {
        name: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 256 } }
        },
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
        }
      }
    }
  };
}

export async function ensureYaraIndex(client: any): Promise<void> {
  if (yaraIndexReady) {
    return;
  }

  if (!yaraIndexEnsureInFlight) {
    yaraIndexEnsureInFlight = (async () => {
      const definition = yaraIndexDefinition();
      const existsResponse = await client.indices.exists({ index: YARA_INDEX_NAME });
      if (indexExistsResponseToBoolean(existsResponse)) {
        yaraIndexReady = true;
        return;
      }

      try {
        await client.indices.create({
          index: YARA_INDEX_NAME,
          body: definition
        });
      } catch (err: any) {
        if (!isAlreadyExistsError(err)) {
          throw err;
        }
      }

      yaraIndexReady = true;
    })().finally(() => {
      yaraIndexEnsureInFlight = null;
    });
  }

  return yaraIndexEnsureInFlight;
}

function nextCustomRuleId(): string {
  return `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizedForgeCoreId(id: unknown): string {
  const raw = String(id ?? '').trim();
  if (!raw) {
    return `forge-core-${Date.now()}`;
  }
  return raw.startsWith('forge-core-') ? raw : `forge-core-${raw}`;
}

async function getRecord(client: any, id: string): Promise<YaraRuleRecord | null> {
  await ensureYaraIndex(client);
  try {
    const response = await client.get({ index: YARA_INDEX_NAME, id });
    return toRecord(id, response?.body?._source ?? response?._source);
  } catch (_err) {
    return null;
  }
}

async function saveRecord(client: any, id: string, record: YaraRuleRecord): Promise<void> {
  await ensureYaraIndex(client);
  const doc: YaraIndexDocument = {
    name: record.name,
    source: record.source,
    enabled: record.enabled,
    severity: record.severity,
    tags: [...record.tags],
    content: record.content,
    updated_at: record.updatedAt,
    validation: cloneValidation(record.validation)
  };
  await client.update({
    index: YARA_INDEX_NAME,
    id,
    refresh: 'wait_for',
    body: {
      doc,
      doc_as_upsert: true
    }
  });
}

export async function listYaraRules(client: any): Promise<YaraRuleSummary[]> {
  await ensureYaraIndex(client);
  let hits: any[] = [];
  try {
    const response = await client.search({
      index: YARA_INDEX_NAME,
      size: 10000,
      body: {
        query: { match_all: {} },
        sort: [{ updated_at: { order: 'desc' } }]
      }
    });
    hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
  } catch (_err) {
    hits = [];
  }

  return hits
    .map((hit) => mapSummaryHit(hit))
    .filter((entry): entry is YaraRuleSummary => entry !== null)
    .sort((left, right) => left.name.localeCompare(right.name));
}

export async function getYaraRule(client: any, id: string): Promise<YaraRuleRecord | null> {
  return getRecord(client, id);
}

/**
 * Fetch ALL existing forge-core rule records in a single search query.
 * Returns a Map keyed by document ID for O(1) lookups during bulk sync.
 */
export async function listExistingForgeCoreRulesForSync(client: any): Promise<Map<string, YaraRuleRecord>> {
  await ensureYaraIndex(client);
  const resultMap = new Map<string, YaraRuleRecord>();
  try {
    const response = await client.search({
      index: YARA_INDEX_NAME,
      size: 10000,
      body: { query: { term: { source: 'forge-core' } } }
    });
    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    for (const hit of hits) {
      const id = String(hit?._id ?? '').trim();
      if (!id) { continue; }
      const record = toRecord(id, hit?._source);
      if (record) {
        resultMap.set(id, record);
      }
    }
  } catch (_err) {
    // Return empty map — signals a full re-import on error.
  }
  return resultMap;
}

/**
 * Retrieve ALL YARA rule records including content in a single search query.
 * Used internally by buildSignedYaraBundle to avoid N individual GETs.
 */
async function getAllYaraRuleRecords(client: any): Promise<YaraRuleRecord[]> {
  await ensureYaraIndex(client);
  try {
    const response = await client.search({
      index: YARA_INDEX_NAME,
      size: 10000,
      body: { query: { match_all: {} } }
    });
    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    return hits
      .map((hit: any) => toRecord(String(hit?._id ?? ''), hit?._source))
      .filter((r: YaraRuleRecord | null): r is YaraRuleRecord => r !== null);
  } catch (_err) {
    return [];
  }
}

/**
 * Bulk-upsert a batch of YaraRuleRecord objects using the OpenSearch bulk API.
 * Processes records in chunks of 500 and refreshes the index once at the end.
 */
async function bulkUpsertYaraRuleRecords(client: any, records: YaraRuleRecord[]): Promise<void> {
  if (records.length === 0) {
    return;
  }
  await ensureYaraIndex(client);
  const chunkSize = 500;
  for (let i = 0; i < records.length; i += chunkSize) {
    const chunk = records.slice(i, i + chunkSize);
    const bulkBody: any[] = [];
    for (const record of chunk) {
      const doc: YaraIndexDocument = {
        name: record.name,
        source: record.source,
        enabled: record.enabled,
        severity: record.severity,
        tags: [...record.tags],
        content: record.content,
        updated_at: record.updatedAt,
        validation: cloneValidation(record.validation)
      };
      bulkBody.push({ update: { _index: YARA_INDEX_NAME, _id: record.id } });
      bulkBody.push({ doc, doc_as_upsert: true });
    }
    await client.bulk({ body: bulkBody, refresh: false });
  }
  // Single index refresh after all chunks are written.
  await client.indices.refresh({ index: YARA_INDEX_NAME });
}

export interface BulkSyncForgeCoreResult {
  imported: number;
  unchanged: number;
  activeRulesQueued: number;
}

/**
 * Sync forge-core rules from a release in bulk:
 * 1. Compare new rules against existingMap in memory (no per-rule GET calls)
 * 2. Write all changed/new rules via a single bulk upsert + one index refresh
 *
 * @param existingMap - Pre-fetched forge-core rule map (call listExistingForgeCoreRulesForSync
 *   once before this call and pass the result here to avoid a redundant search).
 */
export async function bulkSyncForgeCoreRules(
  client: any,
  sources: Array<{ id: unknown; name: unknown; content: unknown; severity?: unknown; tags?: unknown }>,
  existingMap: Map<string, YaraRuleRecord>
): Promise<BulkSyncForgeCoreResult> {
  let imported = 0;
  let unchanged = 0;
  let activeRulesQueued = 0;
  const toSave: YaraRuleRecord[] = [];

  for (const source of sources) {
    const id = normalizedForgeCoreId(source.id);
    const existing = existingMap.get(id);
    const name = sanitizeRuleName(source.name);
    const content = String(source.content ?? '');
    const validation = validateYaraContent(content, name);

    // Determine enabled state:
    // - New rule: default to enabled (true)
    // - Existing rule that was auto-disabled due to a past validation failure and is now
    //   valid: re-enable it automatically
    // - Existing rule that a user manually disabled (was valid when disabled): keep disabled
    let desiredEnabled: boolean;
    if (existing) {
      if (!existing.enabled && existing.validation.status === 'invalid' && validation.status === 'valid') {
        desiredEnabled = true;
      } else {
        desiredEnabled = existing.enabled;
      }
    } else {
      desiredEnabled = true;
    }
    if (validation.status === 'invalid') {
      desiredEnabled = false;
    }

    const candidate: YaraRuleRecord = {
      id,
      name,
      source: 'forge-core',
      enabled: desiredEnabled,
      severity: sanitizeSeverity(source.severity),
      tags: normalizeTags(source.tags),
      content,
      updatedAt: nowIso(),
      validation
    };

    if (existing) {
      const changed =
        existing.content !== candidate.content ||
        existing.name !== candidate.name ||
        existing.enabled !== candidate.enabled ||
        existing.severity !== candidate.severity ||
        JSON.stringify(existing.tags) !== JSON.stringify(candidate.tags) ||
        existing.validation.status !== candidate.validation.status ||
        JSON.stringify(existing.validation.errors) !== JSON.stringify(candidate.validation.errors) ||
        JSON.stringify(existing.validation.warnings) !== JSON.stringify(candidate.validation.warnings);
      if (!changed) {
        unchanged += 1;
        if (existing.enabled) {
          activeRulesQueued += 1;
        }
        continue;
      }
    }

    toSave.push(candidate);
    imported += 1;
    if (candidate.enabled) {
      activeRulesQueued += 1;
    }
  }

  if (toSave.length > 0) {
    await bulkUpsertYaraRuleRecords(client, toSave);
  }

  return { imported, unchanged, activeRulesQueued };
}

export async function addCustomYaraRule(
  client: any,
  input: { name: unknown; content: unknown; severity?: unknown; tags?: unknown }
): Promise<YaraRuleRecord> {
  const name = sanitizeRuleName(input.name);
  const content = String(input.content ?? '');
  const validation = validateYaraContent(content, name);
  const record: YaraRuleRecord = {
    id: nextCustomRuleId(),
    name,
    source: 'custom',
    enabled: validation.status === 'valid',
    severity: sanitizeSeverity(input.severity),
    tags: normalizeTags(input.tags),
    content,
    updatedAt: nowIso(),
    validation
  };
  await saveRecord(client, record.id, record);
  return record;
}

export async function upsertForgeCoreYaraRule(
  client: any,
  input: { id: unknown; name: unknown; content: unknown; severity?: unknown; tags?: unknown; enabled?: unknown }
): Promise<{ rule: YaraRuleRecord; created: boolean; changed: boolean }> {
  const id = normalizedForgeCoreId(input.id);
  const existing = await getRecord(client, id);
  const name = sanitizeRuleName(input.name);
  const content = String(input.content ?? '');
  const validation = validateYaraContent(content, name);
  const candidate: YaraRuleRecord = {
    id,
    name,
    source: 'forge-core',
    enabled: input.enabled !== undefined ? Boolean(input.enabled) : existing ? existing.enabled : true,
    severity: sanitizeSeverity(input.severity),
    tags: normalizeTags(input.tags),
    content,
    updatedAt: nowIso(),
    validation
  };

  if (candidate.validation.status === 'invalid') {
    candidate.enabled = false;
  }

  if (existing) {
    const changed =
      existing.content !== candidate.content ||
      existing.name !== candidate.name ||
      existing.enabled !== candidate.enabled ||
      existing.severity !== candidate.severity ||
      JSON.stringify(existing.tags) !== JSON.stringify(candidate.tags) ||
      existing.validation.status !== candidate.validation.status ||
      JSON.stringify(existing.validation.errors) !== JSON.stringify(candidate.validation.errors) ||
      JSON.stringify(existing.validation.warnings) !== JSON.stringify(candidate.validation.warnings);
    if (!changed) {
      return { rule: existing, created: false, changed: false };
    }
  }

  await saveRecord(client, id, candidate);
  return { rule: candidate, created: !existing, changed: true };
}

export async function getExistingForgeCoreRuleState(client: any, id: unknown): Promise<{ enabled: boolean } | null> {
  const existing = await getRecord(client, normalizedForgeCoreId(id));
  return existing ? { enabled: existing.enabled } : null;
}

export async function updateYaraRule(
  client: any,
  id: string,
  patch: { enabled?: unknown; content?: unknown; severity?: unknown; tags?: unknown; name?: unknown }
): Promise<{ updated: YaraRuleRecord | null; error?: string }> {
  const target = await getRecord(client, id);
  if (!target) {
    return { updated: null, error: 'Rule not found.' };
  }

  const next: YaraRuleRecord = {
    ...target,
    tags: [...target.tags],
    validation: cloneValidation(target.validation)
  };

  if (patch.name !== undefined) {
    next.name = sanitizeRuleName(patch.name);
  }
  if (patch.content !== undefined) {
    next.content = String(patch.content ?? '');
  }
  if (patch.severity !== undefined) {
    next.severity = sanitizeSeverity(patch.severity);
  }
  if (patch.tags !== undefined) {
    next.tags = normalizeTags(patch.tags);
  }
  if (patch.enabled !== undefined) {
    next.enabled = Boolean(patch.enabled);
  }

  next.validation = validateYaraContent(next.content, next.name);
  if (next.validation.status === 'invalid') {
    next.enabled = false;
  }
  next.updatedAt = nowIso();
  await saveRecord(client, id, next);
  return { updated: next };
}

export async function deleteCustomYaraRule(client: any, id: string): Promise<{ deleted: boolean; error?: string }> {
  await ensureYaraIndex(client);
  try {
    await client.delete({ index: YARA_INDEX_NAME, id, refresh: 'wait_for' });
    return { deleted: true };
  } catch (_err) {
    return { deleted: false, error: 'Rule not found.' };
  }
}

function buildBundleRules(records: YaraRuleRecord[]): BundleRuleEntry[] {
  return records
    .filter((rule) => rule.validation.status === 'valid')
    .map((rule) => ({
      id: rule.id,
      filename: `${rule.id}.yar`,
      content: rule.content,
      sha256: crypto.createHash('sha256').update(rule.content, 'utf8').digest('hex'),
      enabled: rule.enabled,
      source: rule.source,
      updatedAt: rule.updatedAt
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
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

function loadBundleStateFile(): PersistedBundleStateFile {
  return readJsonFile<PersistedBundleStateFile>(BUNDLE_STATE_FILE, defaultBundleStateFile());
}

function saveBundleStateFile(state: PersistedBundleStateFile): void {
  writeJsonFile(BUNDLE_STATE_FILE, state);
}

function bundleCachePath(policyId: string): string {
  return resolvePluginDataPath('registries', `yara_bundle_cache_${encodeURIComponent(policyId)}.json`);
}

export function getSigningReadiness(): { ready: boolean; reason?: string } {
  const key = getSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

export async function buildSignedYaraBundle(
  client: any,
  policyId: string
): Promise<{ bundle?: SignedBundleResponse; error?: string }> {
  const keyResult = getSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    return { error: keyResult.error ?? 'Signing key is unavailable.' };
  }

  // Fetch all rules with content in a single search query (avoids N individual GETs).
  const records = await getAllYaraRuleRecords(client);

  const bundleRules = buildBundleRules(records);
  const activeChecksums = bundleRules
    .filter((entry) => entry.enabled)
    .map((entry) => entry.sha256)
    .sort((left, right) => left.localeCompare(right));

  const digest = bundleContentDigest(policyId, bundleRules, activeChecksums);
  const state = loadBundleStateFile();
  const existingBundle = state.bundleStates[policyId];
  const bundleState =
    existingBundle && existingBundle.content_digest === digest
      ? existingBundle
      : {
          bundle_version: (existingBundle?.bundle_version ?? 0) + 1,
          generated_at: nowIso(),
          content_digest: digest
        };

  const cachePath = bundleCachePath(policyId);
  if (existingBundle && existingBundle.content_digest === digest) {
    const cached = readJsonFile<SignedBundleResponse | null>(cachePath, null);
    if (cached && cached.bundle_version === bundleState.bundle_version) {
      return { bundle: cached };
    }
  }

  if (!existingBundle || existingBundle.content_digest !== digest) {
    state.bundleStates[policyId] = bundleState;
    saveBundleStateFile(state);
  }

  const payload: BundlePayload = {
    manifest_version: 1,
    policy_id: policyId,
    bundle_version: bundleState.bundle_version,
    generated_at: bundleState.generated_at,
    signing_alg: 'ed25519',
    rules: bundleRules,
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