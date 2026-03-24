declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

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

interface SigningKeyResult {
  ok: boolean;
  privateKey?: any;
  error?: string;
}

const builtinRules = new Map<string, YaraRuleRecord>();
const customRules = new Map<string, YaraRuleRecord>();
const forgeCoreRules = new Map<string, YaraRuleRecord>();
let bundleVersionCounter = 1;

function isoNow(): string {
  return new Date().toISOString();
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
  if (candidate.length === 0) {
    return `custom_rule_${Date.now()}`;
  }
  return candidate.slice(0, 160);
}

function ensureBuiltins(): void {
  if (builtinRules.size > 0) {
    return;
  }

  const builtinEntries: Array<Pick<YaraRuleRecord, 'id' | 'name' | 'severity' | 'tags' | 'content'>> = [
    {
      id: 'builtin-suspicious-powershell',
      name: 'Suspicious PowerShell EncodedCommand',
      severity: 'high',
      tags: ['builtin', 'powershell', 'execution'],
      content:
        'rule suspicious_powershell_encoded_command {\n' +
        '  strings:\n' +
        '    $cmd = "-EncodedCommand" nocase\n' +
        '  condition:\n' +
        '    $cmd\n' +
        '}'
    },
    {
      id: 'builtin-ransom-note-string',
      name: 'Ransom Note Indicator String',
      severity: 'critical',
      tags: ['builtin', 'ransomware', 'files'],
      content:
        'rule ransom_note_indicator_string {\n' +
        '  strings:\n' +
        '    $s1 = "your files have been encrypted" nocase\n' +
        '  condition:\n' +
        '    $s1\n' +
        '}'
    }
  ];

  const now = isoNow();
  for (const entry of builtinEntries) {
    const validation = validateYaraContent(entry.content, entry.name);
    builtinRules.set(entry.id, {
      id: entry.id,
      name: entry.name,
      source: 'builtin',
      enabled: true,
      severity: entry.severity,
      tags: entry.tags,
      content: entry.content,
      updatedAt: now,
      validation
    });
  }
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
      warnings.push(
        `Rule declaration name (${ruleNameMatch[1]}) does not match provided name (${normalizedExpected}).`
      );
    }
  }

  if (!/\bcondition\s*:/i.test(content)) {
    errors.push('Missing YARA condition section.');
  }

  let openBraces = 0;
  for (const char of content) {
    if (char === '{') {
      openBraces += 1;
    }
    if (char === '}') {
      openBraces -= 1;
      if (openBraces < 0) {
        errors.push('Mismatched braces found in rule content.');
        break;
      }
    }
  }

  if (openBraces !== 0) {
    errors.push('Unbalanced braces in rule content.');
  }

  return {
    status: errors.length > 0 ? 'invalid' : 'valid',
    errors,
    warnings,
    checkedAt: isoNow()
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

function allRules(): YaraRuleRecord[] {
  ensureBuiltins();
  return [...builtinRules.values(), ...customRules.values(), ...forgeCoreRules.values()].map(cloneRule);
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
  ensureBuiltins();
  const rule = customRules.get(id) ?? forgeCoreRules.get(id) ?? builtinRules.get(id);
  return rule ? cloneRule(rule) : null;
}

function nextCustomRuleId(): string {
  return `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function addCustomYaraRule(input: {
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
}): YaraRuleRecord {
  ensureBuiltins();
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

  customRules.set(record.id, record);
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
  ensureBuiltins();

  const idRaw = String(input.id ?? '').trim();
  const id = idRaw.startsWith('forge-core-') ? idRaw : `forge-core-${idRaw || Date.now()}`;
  const name = sanitizeRuleName(input.name);
  const content = String(input.content ?? '');
  const validation = validateYaraContent(content, name);

  const existing = forgeCoreRules.get(id);
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

  forgeCoreRules.set(id, candidate);
  return { rule: cloneRule(candidate), created: !existing, changed: true };
}

export function getExistingForgeCoreRuleState(id: unknown): { enabled: boolean } | null {
  ensureBuiltins();
  const idRaw = String(id ?? '').trim();
  const normalizedId = idRaw.startsWith('forge-core-') ? idRaw : `forge-core-${idRaw || ''}`;
  const existing = forgeCoreRules.get(normalizedId);
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
  ensureBuiltins();
  const target = customRules.get(id) ?? forgeCoreRules.get(id) ?? builtinRules.get(id);
  if (!target) {
    return { updated: null, error: 'Rule not found.' };
  }

  if (target.source === 'builtin' && patch.content !== undefined) {
    return { updated: null, error: 'Builtin rule content is read-only.' };
  }

  const next: YaraRuleRecord = cloneRule(target);

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

  if (next.source === 'custom') {
    customRules.set(id, next);
  } else if (next.source === 'forge-core') {
    forgeCoreRules.set(id, next);
  } else {
    builtinRules.set(id, next);
  }

  return { updated: cloneRule(next) };
}

export function deleteCustomYaraRule(id: string): { deleted: boolean; error?: string } {
  ensureBuiltins();
  const builtin = builtinRules.get(id);
  if (builtin) {
    return { deleted: false, error: 'Builtin rules cannot be deleted.' };
  }
  const deleted = customRules.delete(id) || forgeCoreRules.delete(id);
  if (!deleted) {
    return { deleted: false, error: 'Rule not found.' };
  }
  return { deleted: true };
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

function parseSigningPrivateKey(): SigningKeyResult {
  const encoded = String(process.env.XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64 ?? '').trim();
  if (!encoded) {
    return {
      ok: false,
      error:
        'XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64 is not configured. Provide base64 raw 32-byte seed or 64-byte private key.'
    };
  }

  let raw: any;
  try {
    raw = BufferCtor.from(encoded, 'base64');
  } catch (_err) {
    return { ok: false, error: 'Signing private key is not valid base64.' };
  }

  if (!raw || !raw.length) {
    return { ok: false, error: 'Signing private key decode produced empty bytes.' };
  }

  let seed = raw;
  if (raw.length === 64) {
    seed = raw.subarray(0, 32);
  }

  if (seed.length !== 32) {
    return {
      ok: false,
      error: `Signing private key must decode to 32-byte seed or 64-byte private key, got ${raw.length} bytes.`
    };
  }

  try {
    const pkcs8Prefix = BufferCtor.from('302e020100300506032b657004220420', 'hex');
    const pkcs8 = BufferCtor.concat([pkcs8Prefix, seed]);
    const privateKey = crypto.createPrivateKey({
      key: pkcs8,
      format: 'der',
      type: 'pkcs8'
    });
    return { ok: true, privateKey };
  } catch (err: any) {
    return {
      ok: false,
      error: `Unable to construct Ed25519 private key: ${String(err?.message ?? err)}`
    };
  }
}

export function getSigningReadiness(): { ready: boolean; reason?: string } {
  const key = parseSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

export function buildSignedYaraBundle(policyId: string): { bundle?: SignedBundleResponse; error?: string } {
  const keyResult = parseSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    return { error: keyResult.error ?? 'Signing key is unavailable.' };
  }

  const bundleRules = buildBundleRules();
  const activeChecksums = bundleRules
    .filter((entry) => entry.enabled)
    .map((entry) => entry.sha256)
    .sort((a, b) => a.localeCompare(b));

  const payload: BundlePayload = {
    manifest_version: 1,
    policy_id: policyId,
    bundle_version: bundleVersionCounter++,
    generated_at: isoNow(),
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
