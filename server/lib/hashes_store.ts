declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

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

interface SigningKeyResult {
  ok: boolean;
  privateKey?: any;
  error?: string;
}

const customRules = new Map<string, HashRuleRecord>();
const malwareBazaarRules = new Map<string, HashRuleRecord>();
let bundleVersionCounter = 1;

function isoNow(): string {
  return new Date().toISOString();
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

function allRules(): HashRuleRecord[] {
  return [...customRules.values(), ...malwareBazaarRules.values()].map(cloneRule);
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
  const rule = customRules.get(id) ?? malwareBazaarRules.get(id);
  return rule ? cloneRule(rule) : null;
}

function nextCustomRuleId(): string {
  return `hash-custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function addCustomHashRule(input: {
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
}): HashRuleRecord {
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

  customRules.set(record.id, record);
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
  const idRaw = String(input.id ?? '').trim();
  const id = idRaw.startsWith('malwarebazaar-') ? idRaw : `malwarebazaar-${idRaw || Date.now()}`;
  const content = String(input.content ?? '');
  const validation = validateHashContent(content);
  const existing = malwareBazaarRules.get(id);

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

  malwareBazaarRules.set(id, candidate);
  return { rule: cloneRule(candidate), created: !existing, changed: true };
}

export function getExistingMalwareBazaarHashRuleState(id: unknown): { enabled: boolean } | null {
  const idRaw = String(id ?? '').trim();
  const normalizedId = idRaw.startsWith('malwarebazaar-') ? idRaw : `malwarebazaar-${idRaw || ''}`;
  const existing = malwareBazaarRules.get(normalizedId);
  return existing ? { enabled: existing.enabled } : null;
}

export function updateHashRule(
  id: string,
  patch: { enabled?: unknown; content?: unknown; severity?: unknown; tags?: unknown; name?: unknown }
): { updated: HashRuleRecord | null; error?: string } {
  const target = customRules.get(id) ?? malwareBazaarRules.get(id);
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
    malwareBazaarRules.set(id, next);
  } else {
    customRules.set(id, next);
  }

  return { updated: cloneRule(next) };
}

export function deleteHashRule(id: string): { deleted: boolean; error?: string } {
  const deleted = customRules.delete(id) || malwareBazaarRules.delete(id);
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
      filename: `${rule.id}.hashes`,
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

export function getHashSigningReadiness(): { ready: boolean; reason?: string } {
  const key = parseSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

export function buildSignedHashBundle(policyId: string): { bundle?: SignedBundleResponse; error?: string } {
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