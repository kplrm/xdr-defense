declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

import { getSigningPrivateKey } from './signing_keys';

export type BehavioralRuleSource = 'custom' | 'sigmahq';
export type RuleValidationStatus = 'valid' | 'invalid';

export interface RuleValidation {
  status: RuleValidationStatus;
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

export interface BehavioralRuleRecord {
  id: string;
  name: string;
  source: BehavioralRuleSource;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  updatedAt: string;
  validation: RuleValidation;
}

export interface BehavioralRuleSummary {
  id: string;
  name: string;
  source: BehavioralRuleSource;
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
  source: BehavioralRuleSource;
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

const customRules = new Map<string, BehavioralRuleRecord>();
const sigmaRules = new Map<string, BehavioralRuleRecord>();
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
    return `behavior_rule_${Date.now()}`;
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

export function validateBehavioralContent(contentRaw: unknown): RuleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const content = String(contentRaw ?? '');

  if (content.trim().length === 0) {
    errors.push('Behavioral rule content cannot be empty.');
  }

  if (content.length > 200_000) {
    errors.push('Behavioral rule content exceeds maximum size (200000 bytes).');
  }

  if (!/^title\s*:\s*.+$/im.test(content)) {
    errors.push('Sigma rule must include a title field.');
  }

  if (!/^detection\s*:/im.test(content)) {
    errors.push('Sigma rule must include a detection section.');
  }

  if (!/^logsource\s*:/im.test(content)) {
    warnings.push('Sigma rule is missing logsource; this may reduce matching quality.');
  }

  return {
    status: errors.length > 0 ? 'invalid' : 'valid',
    errors,
    warnings,
    checkedAt: isoNow()
  };
}

function cloneRule(rule: BehavioralRuleRecord): BehavioralRuleRecord {
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

function allRules(): BehavioralRuleRecord[] {
  return [...customRules.values(), ...sigmaRules.values()].map(cloneRule);
}

export function listBehavioralRules(): BehavioralRuleSummary[] {
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

export function getBehavioralRule(id: string): BehavioralRuleRecord | null {
  const rule = customRules.get(id) ?? sigmaRules.get(id);
  return rule ? cloneRule(rule) : null;
}

function nextCustomRuleId(): string {
  return `behavior-custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function addCustomBehavioralRule(input: {
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
}): BehavioralRuleRecord {
  const content = String(input.content ?? '');
  const validation = validateBehavioralContent(content);
  const record: BehavioralRuleRecord = {
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

export function upsertSigmaBehavioralRule(input: {
  id: unknown;
  name: unknown;
  content: unknown;
  severity?: unknown;
  tags?: unknown;
  enabled?: unknown;
}): { rule: BehavioralRuleRecord; created: boolean; changed: boolean } {
  const idRaw = String(input.id ?? '').trim();
  const id = idRaw.startsWith('sigmahq-') ? idRaw : `sigmahq-${idRaw || Date.now()}`;
  const content = String(input.content ?? '');
  const validation = validateBehavioralContent(content);
  const existing = sigmaRules.get(id);

  const candidate: BehavioralRuleRecord = {
    id,
    name: sanitizeRuleName(input.name),
    source: 'sigmahq',
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

  sigmaRules.set(id, candidate);
  return { rule: cloneRule(candidate), created: !existing, changed: true };
}

export function getExistingSigmaBehavioralRuleState(id: unknown): { enabled: boolean } | null {
  const idRaw = String(id ?? '').trim();
  const normalizedId = idRaw.startsWith('sigmahq-') ? idRaw : `sigmahq-${idRaw || ''}`;
  const existing = sigmaRules.get(normalizedId);
  return existing ? { enabled: existing.enabled } : null;
}

export function updateBehavioralRule(
  id: string,
  patch: { enabled?: unknown; content?: unknown; severity?: unknown; tags?: unknown; name?: unknown }
): { updated: BehavioralRuleRecord | null; error?: string } {
  const target = customRules.get(id) ?? sigmaRules.get(id);
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

  next.validation = validateBehavioralContent(next.content);
  if (next.validation.status === 'invalid') {
    next.enabled = false;
  }
  next.updatedAt = isoNow();

  if (next.source === 'sigmahq') {
    sigmaRules.set(id, next);
  } else {
    customRules.set(id, next);
  }

  return { updated: cloneRule(next) };
}

export function deleteBehavioralRule(id: string): { deleted: boolean; error?: string } {
  const deleted = customRules.delete(id) || sigmaRules.delete(id);
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
      filename: `${rule.id}.sigma`,
      content: rule.content,
      sha256: crypto.createHash('sha256').update(rule.content, 'utf8').digest('hex'),
      enabled: rule.enabled,
      source: rule.source,
      updatedAt: rule.updatedAt
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

export function getBehavioralSigningReadiness(): { ready: boolean; reason?: string } {
  const key = getSigningPrivateKey();
  if (!key.ok) {
    return { ready: false, reason: key.error };
  }
  return { ready: true };
}

export function buildSignedBehavioralBundle(policyId: string): { bundle?: SignedBundleResponse; error?: string } {
  const keyResult = getSigningPrivateKey();
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