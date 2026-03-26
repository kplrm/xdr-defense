declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';
import { getSigningPrivateKey } from './signing_keys';

export type HashRuleSource = 'custom' | 'malwarebazaar';
export type RuleValidationStatus = 'valid' | 'invalid';

export interface RuleValidation {
  status: RuleValidationStatus;
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

export interface HashRuleRecord {
  id: string;
  name: string;
  source: HashRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  updatedAt: string;
  validation: RuleValidation;
}

export interface HashRuleSummary {
  id: string;
  name: string;
  source: HashRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  updatedAt: string;
  validation: RuleValidation;
}

export interface BundleRuleEntry {
  id: string;
  filename: string;
  content: string;
  sha256: string;
  enabled: boolean;
  source: HashRuleSource;
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

interface PersistedHashState {
  version: 1;
  customRules: Record<string, HashRuleRecord>;
  malwareBazaarRules: Record<string, HashRuleRecord>;
  bundleStates: Record<string, PersistedBundleState>;
}

const HASH_STATE_FILE = resolvePluginDataPath('registries', 'hash_rules.json');
const LEGACY_MALWARE_BAZAAR_RULE_ID = 'malwarebazaar-recent-feed';
let stateCache: PersistedHashState | null = null;

function isoNow(): string {
  return new Date().toISOString();
}

function defaultState(): PersistedHashState {
  return {
    version: 1,
    customRules: {},
    malwareBazaarRules: {},
    bundleStates: {}
  };
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
    return `hash_rule_${Date.now()}`;
  }
  return candidate.slice(0, 160);
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

function isHashLine(line: string): boolean {
  return (
    /^(md5:[a-f0-9]{32})(\s+#.*)?$/i.test(line) ||
    /^(sha1:[a-f0-9]{40})(\s+#.*)?$/i.test(line) ||
    /^(sha256:[a-f0-9]{64})(\s+#.*)?$/i.test(line) ||
    /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})(\s+#.*)?$/i.test(line)
  );
}

function extractSha256Lines(contentRaw: unknown): string[] {
  const entries = new Set<string>();
  for (const rawLine of String(contentRaw ?? '').split(/\r?\n/)) {
    const line = rawLine.trim().toLowerCase();
    const match = line.match(/^sha256:([a-f0-9]{64})$/) ?? line.match(/^([a-f0-9]{64})$/);
    if (match) {
      entries.add(match[1]);
    }
  }
  return [...entries];
}

function malwareBazaarRuleIdForSha256(sha256: string): string {
  return `malwarebazaar-sha256-${sha256.toLowerCase()}`;
}

function malwareBazaarRuleNameForSha256(sha256: string): string {
  return `MalwareBazaar SHA256 ${sha256.slice(0, 12)}`;
}

function migrateLegacyMalwareBazaarAggregateRule(state: PersistedHashState): boolean {
  const legacy = state.malwareBazaarRules[LEGACY_MALWARE_BAZAAR_RULE_ID];
  if (!legacy) {
    return false;
  }

  const hashes = extractSha256Lines(legacy.content);
  for (const sha256 of hashes) {
    const id = malwareBazaarRuleIdForSha256(sha256);
    if (state.malwareBazaarRules[id]) {
      continue;
    }

    const content = `sha256:${sha256}`;
    const validation = validateHashContent(content);
    state.malwareBazaarRules[id] = {
      id,
      name: malwareBazaarRuleNameForSha256(sha256),
      source: 'malwarebazaar',
      enabled: legacy.enabled && validation.status === 'valid',
      severity: sanitizeSeverity(legacy.severity),
      tags: normalizeTags(legacy.tags),
      content,
      updatedAt: legacy.updatedAt || isoNow(),
      validation
    };
  }

  delete state.malwareBazaarRules[LEGACY_MALWARE_BAZAAR_RULE_ID];
  return true;
}

export function validateHashContent(contentRaw: unknown): RuleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const content = String(contentRaw ?? '');

  if (content.trim().length === 0) {
    errors.push('Hash content cannot be empty.');
  }
  if (content.length > 200_000) {
    errors.push('Hash content exceeds maximum size (200000 bytes).');
  }

  const lines = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length === 0) {
    errors.push('At least one hash entry is required.');
  }

  const invalidLines: string[] = [];
  for (const line of lines) {
    if (!isHashLine(line)) {
      invalidLines.push(line);
    }
  }
  if (invalidLines.length > 0) {
    errors.push(`Invalid hash lines found: ${invalidLines.slice(0, 3).join(' | ')}`);
  }

  if (!/sha256:/i.test(content) && !/^[a-f0-9]{64}(\s+#.*)?$/im.test(content)) {
    warnings.push('No SHA256 entries found; SHA256 is recommended for stronger matching.');
  }

  return {
    status: errors.length > 0 ? 'invalid' : 'valid',
    errors,
    warnings,
    checkedAt: isoNow()
  };
}

function cloneRule(rule: HashRuleRecord): HashRuleRecord {
  return {
    ...rule,
    tags: [...rule.tags],
    validation: {
      ...rule.validation,
      errors: [...rule.validation.errors],
      warnings: [...rule.validation.warnings]
    }
  };
}

function normalizeRule(source: HashRuleSource, raw: unknown): HashRuleRecord | null {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const id = String(record.id ?? '').trim();
  const name = sanitizeRuleName(record.name);
  const content = String(record.content ?? '');
  if (!id || !content) {
    return null;
  }

  const validationRaw = record.validation as Record<string, unknown> | undefined;
  const validation: RuleValidation = validationRaw && typeof validationRaw === 'object'
    ? {
        status: validationRaw.status === 'invalid' ? 'invalid' : 'valid',
        errors: Array.isArray(validationRaw.errors) ? validationRaw.errors.map((entry) => String(entry)) : [],
        warnings: Array.isArray(validationRaw.warnings) ? validationRaw.warnings.map((entry) => String(entry)) : [],
        checkedAt: String(validationRaw.checkedAt ?? isoNow())
      }
    : validateHashContent(content);

  return {
    id,
    name,
    source,
    enabled: Boolean(record.enabled) && validation.status === 'valid',
    severity: sanitizeSeverity(record.severity),
    tags: normalizeTags(record.tags),
    content,
    updatedAt: String(record.updatedAt ?? isoNow()),
    validation
  };
}

function loadState(): PersistedHashState {
  if (stateCache) {
    return stateCache;
  }

  const raw = readJsonFile<PersistedHashState>(HASH_STATE_FILE, defaultState());
  const customRules: Record<string, HashRuleRecord> = {};
  const malwareBazaarRules: Record<string, HashRuleRecord> = {};

  for (const [id, value] of Object.entries(raw?.customRules ?? {})) {
    const normalized = normalizeRule('custom', { id, ...(value as object) });
    if (normalized) {
      customRules[id] = normalized;
    }
  }

  for (const [id, value] of Object.entries(raw?.malwareBazaarRules ?? {})) {
    const normalized = normalizeRule('malwarebazaar', { id, ...(value as object) });
    if (normalized) {
      malwareBazaarRules[id] = normalized;
    }
  }

  stateCache = {
    version: 1,
    customRules,
    malwareBazaarRules,
    bundleStates: raw?.bundleStates && typeof raw.bundleStates === 'object' ? raw.bundleStates : {}
  };

  if (migrateLegacyMalwareBazaarAggregateRule(stateCache)) {
    saveState(stateCache);
  }

  return stateCache;
}

function saveState(state: PersistedHashState): void {
  stateCache = state;
  writeJsonFile(HASH_STATE_FILE, state);
}

function nextCustomRuleId(): string {
  return `hash-custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function allRules(): HashRuleRecord[] {
  const state = loadState();
  return [...Object.values(state.customRules), ...Object.values(state.malwareBazaarRules)]
    .map(cloneRule)
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function listHashRules(): HashRuleSummary[] {
  return allRules().map((rule) => ({
    id: rule.id,
    name: rule.name,
    source: rule.source,
    enabled: rule.enabled,
    severity: rule.severity,
    tags: [...rule.tags],
    updatedAt: rule.updatedAt,
    validation: {
      ...rule.validation,
      errors: [...rule.validation.errors],
      warnings: [...rule.validation.warnings]
    }
  }));
}

export function getHashRule(id: string): HashRuleRecord | null {
  const state = loadState();
  const rule = state.customRules[id] ?? state.malwareBazaarRules[id];
  return rule ? cloneRule(rule) : null;
}

export function addCustomHashRule(input: {
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
}): HashRuleRecord {
  const state = loadState();
  const content = String(input.content ?? '');
  const validation = validateHashContent(content);
  const record: HashRuleRecord = {
    id: nextCustomRuleId(),
    name: sanitizeRuleName(input.name),
    source: 'custom',
    enabled: validation.status === 'valid',
    severity: sanitizeSeverity(input.severity),
    tags: normalizeTags(input.tags),
    content,
    updatedAt: isoNow(),
    validation
  };
  state.customRules[record.id] = record;
  saveState(state);
  return cloneRule(record);
}

export function upsertMalwareBazaarHashRule(input: {
  id: unknown;
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
  enabled?: unknown;
}): { rule: HashRuleRecord; created: boolean; changed: boolean } {
  const state = loadState();
  const idRaw = String(input.id ?? '').trim();
  const id = idRaw.startsWith('malwarebazaar-') ? idRaw : `malwarebazaar-${idRaw || Date.now()}`;
  const content = String(input.content ?? '');
  const validation = validateHashContent(content);
  const existing = state.malwareBazaarRules[id];

  const candidate: HashRuleRecord = {
    id,
    name: sanitizeRuleName(input.name),
    source: 'malwarebazaar',
    enabled: input.enabled !== undefined ? Boolean(input.enabled) : true,
    severity: sanitizeSeverity(input.severity),
    tags: normalizeTags(input.tags),
    content,
    updatedAt: isoNow(),
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
      existing.validation.status !== candidate.validation.status;

    if (!changed) {
      return { rule: cloneRule(existing), created: false, changed: false };
    }
  }

  state.malwareBazaarRules[id] = candidate;
  saveState(state);
  return { rule: cloneRule(candidate), created: !existing, changed: true };
}

export function getExistingMalwareBazaarHashRuleState(id: unknown): { enabled: boolean } | null {
  const state = loadState();
  const idRaw = String(id ?? '').trim();
  const normalizedId = idRaw.startsWith('malwarebazaar-') ? idRaw : `malwarebazaar-${idRaw || ''}`;
  const existing = state.malwareBazaarRules[normalizedId];
  return existing ? { enabled: existing.enabled } : null;
}

export function getMalwareBazaarRuleBySha256(sha256: string): HashRuleRecord | null {
  const state = loadState();
  const id = malwareBazaarRuleIdForSha256(sha256);
  const rule = state.malwareBazaarRules[id];
  return rule ? cloneRule(rule) : null;
}

export function listMalwareBazaarHashRules(): HashRuleSummary[] {
  const state = loadState();
  return Object.values(state.malwareBazaarRules)
    .map(cloneRule)
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((rule) => ({
      id: rule.id,
      name: rule.name,
      source: rule.source,
      enabled: rule.enabled,
      severity: rule.severity,
      tags: [...rule.tags],
      updatedAt: rule.updatedAt,
      validation: {
        ...rule.validation,
        errors: [...rule.validation.errors],
        warnings: [...rule.validation.warnings]
      }
    }));
}

export function removeLegacyMalwareBazaarAggregateRule(): boolean {
  const state = loadState();
  if (!state.malwareBazaarRules[LEGACY_MALWARE_BAZAAR_RULE_ID]) {
    return false;
  }
  delete state.malwareBazaarRules[LEGACY_MALWARE_BAZAAR_RULE_ID];
  saveState(state);
  return true;
}

export function malwareBazaarIdForHash(sha256: string): string {
  return malwareBazaarRuleIdForSha256(sha256);
}

export function malwareBazaarNameForHash(sha256: string): string {
  return malwareBazaarRuleNameForSha256(sha256);
}

export function updateHashRule(
  id: string,
  patch: { enabled?: unknown; content?: unknown; severity?: unknown; tags?: unknown; name?: unknown }
): { updated: HashRuleRecord | null; error?: string } {
  const state = loadState();
  const target = state.customRules[id] ?? state.malwareBazaarRules[id];
  if (!target) {
    return { updated: null, error: 'Rule not found.' };
  }

  const next = cloneRule(target);
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

  next.validation = validateHashContent(next.content);
  if (next.validation.status === 'invalid') {
    next.enabled = false;
  }
  next.updatedAt = isoNow();

  if (next.source === 'malwarebazaar') {
    state.malwareBazaarRules[id] = next;
  } else {
    state.customRules[id] = next;
  }
  saveState(state);

  return { updated: cloneRule(next) };
}

export function deleteHashRule(id: string): { deleted: boolean; error?: string } {
  const state = loadState();
  if (state.customRules[id]) {
    delete state.customRules[id];
    saveState(state);
    return { deleted: true };
  }
  if (state.malwareBazaarRules[id]) {
    delete state.malwareBazaarRules[id];
    saveState(state);
    return { deleted: true };
  }
  return { deleted: false, error: 'Rule not found.' };
}

function buildHashYamlContent(rule: HashRuleRecord): string {
  const lines = rule.content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));

  const entries: string[] = [];
  for (const line of lines) {
    let sha256 = '';
    if (/^sha256:[a-f0-9]{64}(\s+#.*)?$/i.test(line)) {
      sha256 = line.split(':')[1].split(/\s/)[0].toLowerCase();
    } else if (/^[a-f0-9]{64}(\s+#.*)?$/.test(line)) {
      sha256 = line.split(/\s/)[0].toLowerCase();
    }
    if (!sha256) {
      continue;
    }
    const escapedName = rule.name.replace(/'/g, "''");
    const nameYaml = /[:#\[\]{},|>&*!?'"\\]/.test(rule.name) ? `'${escapedName}'` : rule.name;
    entries.push(`  - sha256: ${sha256}\n    name: ${nameYaml}\n    severity: ${rule.severity}\n    source: ${rule.source}`);
  }

  if (entries.length === 0) {
    return 'hashes: []\n';
  }
  return `hashes:\n${entries.join('\n')}\n`;
}

function buildBundleRules(): BundleRuleEntry[] {
  return allRules()
    .filter((rule) => rule.validation.status === 'valid')
    .map((rule) => {
      const content = buildHashYamlContent(rule);
      return {
        id: rule.id,
        filename: `${rule.id}.yaml`,
        content,
        sha256: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
        enabled: rule.enabled,
        source: rule.source,
        updatedAt: rule.updatedAt
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
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

export function getHashSigningReadiness(): { ready: boolean; reason?: string } {
  const key = getSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

export function buildSignedHashBundle(policyId: string): { bundle?: SignedBundleResponse; error?: string } {
  const keyResult = getSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    return { error: keyResult.error ?? 'Signing key is unavailable.' };
  }

  const state = loadState();
  const bundleRules = buildBundleRules();
  const activeChecksums = bundleRules
    .filter((entry) => entry.enabled)
    .map((entry) => entry.sha256)
    .sort((a, b) => a.localeCompare(b));

  const digest = bundleContentDigest(policyId, bundleRules, activeChecksums);
  const existingBundle = state.bundleStates[policyId];
  const bundleState =
    existingBundle && existingBundle.content_digest === digest
      ? existingBundle
      : {
          bundle_version: (existingBundle?.bundle_version ?? 0) + 1,
          generated_at: isoNow(),
          content_digest: digest
        };

  if (!existingBundle || existingBundle.content_digest !== digest) {
    state.bundleStates[policyId] = bundleState;
    saveState(state);
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

  return {
    bundle: {
      ...payload,
      signature_base64: signature.toString('base64'),
      signed_payload_base64: payloadBytes.toString('base64')
    }
  };
}
