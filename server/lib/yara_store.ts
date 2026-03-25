declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';
import { getSigningPrivateKey } from './signing_keys';

export type YaraRuleSource = 'builtin' | 'custom' | 'forge-core';
export type YaraValidationStatus = 'valid' | 'invalid';

export interface YaraRuleValidation {
  status: YaraValidationStatus;
  errors: string[];
  warnings: string[];
  checkedAt: string;
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

interface PersistedYaraState {
  version: 1;
  customRules: Record<string, YaraRuleRecord>;
  forgeCoreRules: Record<string, YaraRuleRecord>;
  bundleStates: Record<string, PersistedBundleState>;
}

const YARA_STATE_FILE = resolvePluginDataPath('registries', 'yara_rules.json');
let stateCache: PersistedYaraState | null = null;

function isoNow(): string {
  return new Date().toISOString();
}

function defaultState(): PersistedYaraState {
  return {
    version: 1,
    customRules: {},
    forgeCoreRules: {},
    bundleStates: {}
  };
}

function cloneRule(rule: YaraRuleRecord): YaraRuleRecord {
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

  // Brace balance check — skips braces inside string literals and comments so
  // YARA rules with `{` inside string values (e.g. $s = "{path}\\file") or
  // inside /* comments */ don't produce false-positive "unbalanced" errors.
  {
    let openBraces = 0;
    let inString = false;
    let inBlockComment = false;
    let inLineComment = false;
    let i = 0;
    let mismatch = false;
    while (i < content.length) {
      const ch = content[i];
      const next = i + 1 < content.length ? content[i + 1] : '';
      if (inLineComment) {
        if (ch === '\n') inLineComment = false;
        i++; continue;
      }
      if (inBlockComment) {
        if (ch === '*' && next === '/') { inBlockComment = false; i += 2; continue; }
        i++; continue;
      }
      if (inString) {
        if (ch === '\\') { i += 2; continue; } // skip escaped character
        if (ch === '"') inString = false;
        i++; continue;
      }
      if (ch === '/' && next === '/') { inLineComment = true; i += 2; continue; }
      if (ch === '/' && next === '*') { inBlockComment = true; i += 2; continue; }
      if (ch === '"') { inString = true; i++; continue; }
      if (ch === '{') { openBraces++; i++; continue; }
      if (ch === '}') {
        openBraces--;
        if (openBraces < 0) {
          errors.push('Mismatched braces found in rule content.');
          mismatch = true;
          break;
        }
        i++; continue;
      }
      i++;
    }
    if (!mismatch && openBraces !== 0) {
      errors.push('Unbalanced braces in rule content.');
    }
  }

  return {
    status: errors.length > 0 ? 'invalid' : 'valid',
    errors,
    warnings,
    checkedAt: isoNow()
  };
}

function normalizeRule(source: YaraRuleSource, raw: unknown): YaraRuleRecord | null {
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
  const validation: YaraRuleValidation = validationRaw && typeof validationRaw === 'object'
    ? {
        status: validationRaw.status === 'invalid' ? 'invalid' : 'valid',
        errors: Array.isArray(validationRaw.errors) ? validationRaw.errors.map((entry) => String(entry)) : [],
        warnings: Array.isArray(validationRaw.warnings) ? validationRaw.warnings.map((entry) => String(entry)) : [],
        checkedAt: String(validationRaw.checkedAt ?? isoNow())
      }
    : validateYaraContent(content, name);

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

function loadState(): PersistedYaraState {
  if (stateCache) {
    return stateCache;
  }

  const raw = readJsonFile<PersistedYaraState>(YARA_STATE_FILE, defaultState());
  const customRules: Record<string, YaraRuleRecord> = {};
  const forgeCoreRules: Record<string, YaraRuleRecord> = {};

  for (const [id, value] of Object.entries(raw?.customRules ?? {})) {
    const normalized = normalizeRule('custom', { id, ...(value as object) });
    if (normalized) {
      customRules[id] = normalized;
    }
  }

  for (const [id, value] of Object.entries(raw?.forgeCoreRules ?? {})) {
    const normalized = normalizeRule('forge-core', { id, ...(value as object) });
    if (normalized) {
      forgeCoreRules[id] = normalized;
    }
  }

  stateCache = {
    version: 1,
    customRules,
    forgeCoreRules,
    bundleStates: raw?.bundleStates && typeof raw.bundleStates === 'object' ? raw.bundleStates : {}
  };

  // One-time migration: re-validate any rule whose only error was the now-fixed
  // naive brace counter producing false positives (e.g. `{` inside string literals).
  let migrationChanges = 0;
  for (const rules of [customRules, forgeCoreRules]) {
    for (const rule of Object.values(rules)) {
      if (
        rule.validation.status === 'invalid' &&
        rule.validation.errors.length > 0 &&
        rule.validation.errors.every(
          (e) => e === 'Unbalanced braces in rule content.' || e === 'Mismatched braces found in rule content.'
        )
      ) {
        const revalidated = validateYaraContent(rule.content);
        if (revalidated.status === 'valid') {
          rule.validation = revalidated;
          rule.enabled = true;
          migrationChanges++;
        }
      }
    }
  }
  if (migrationChanges > 0) {
    saveState(stateCache);
  }

  return stateCache;
}

function saveState(state: PersistedYaraState): void {
  stateCache = state;
  writeJsonFile(YARA_STATE_FILE, state);
}

function nextCustomRuleId(): string {
  return `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function allRules(): YaraRuleRecord[] {
  const state = loadState();
  return [...Object.values(state.customRules), ...Object.values(state.forgeCoreRules)]
    .map(cloneRule)
    .sort((a, b) => a.name.localeCompare(b.name));
}

function buildBundleRules(): BundleRuleEntry[] {
  return allRules()
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

export function listYaraRules(): YaraRuleSummary[] {
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

export function getYaraRule(id: string): YaraRuleRecord | null {
  const state = loadState();
  const rule = state.customRules[id] ?? state.forgeCoreRules[id];
  return rule ? cloneRule(rule) : null;
}

export function addCustomYaraRule(input: {
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
}): YaraRuleRecord {
  const state = loadState();
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
    updatedAt: isoNow(),
    validation
  };

  state.customRules[record.id] = record;
  saveState(state);
  return cloneRule(record);
}

export function upsertForgeCoreYaraRule(input: {
  id: unknown;
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
  enabled?: unknown;
}): { rule: YaraRuleRecord; created: boolean; changed: boolean } {
  const state = loadState();
  const idRaw = String(input.id ?? '').trim();
  const id = idRaw.startsWith('forge-core-') ? idRaw : `forge-core-${idRaw || Date.now()}`;
  const name = sanitizeRuleName(input.name);
  const content = String(input.content ?? '');
  const validation = validateYaraContent(content, name);
  const existing = state.forgeCoreRules[id];

  const candidate: YaraRuleRecord = {
    id,
    name,
    source: 'forge-core',
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

  state.forgeCoreRules[id] = candidate;
  saveState(state);
  return { rule: cloneRule(candidate), created: !existing, changed: true };
}

export function getExistingForgeCoreRuleState(id: unknown): { enabled: boolean } | null {
  const state = loadState();
  const idRaw = String(id ?? '').trim();
  const normalizedId = idRaw.startsWith('forge-core-') ? idRaw : `forge-core-${idRaw || ''}`;
  const existing = state.forgeCoreRules[normalizedId];
  return existing ? { enabled: existing.enabled } : null;
}

export function updateYaraRule(
  id: string,
  patch: {
    enabled?: unknown;
    content?: unknown;
    severity?: unknown;
    tags?: unknown;
    name?: unknown;
  }
): { updated: YaraRuleRecord | null; error?: string } {
  const state = loadState();
  const target = state.customRules[id] ?? state.forgeCoreRules[id];
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

  next.validation = validateYaraContent(next.content, next.name);
  if (next.validation.status === 'invalid') {
    next.enabled = false;
  }
  next.updatedAt = isoNow();

  if (next.source === 'forge-core') {
    state.forgeCoreRules[id] = next;
  } else {
    state.customRules[id] = next;
  }
  saveState(state);

  return { updated: cloneRule(next) };
}

export function deleteCustomYaraRule(id: string): { deleted: boolean; error?: string } {
  const state = loadState();
  if (state.customRules[id]) {
    delete state.customRules[id];
    saveState(state);
    return { deleted: true };
  }
  if (state.forgeCoreRules[id]) {
    delete state.forgeCoreRules[id];
    saveState(state);
    return { deleted: true };
  }
  return { deleted: false, error: 'Rule not found.' };
}

export function getSigningReadiness(): { ready: boolean; reason?: string } {
  const key = getSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

export function buildSignedYaraBundle(policyId: string): { bundle?: SignedBundleResponse; error?: string } {
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
