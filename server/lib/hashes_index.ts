declare const require: any;

const crypto = require('crypto');

export const HASHES_INDEX_NAME = '.xdr-defense-hashes';

export interface RuleValidation {
  status: 'valid' | 'invalid';
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

export interface HashIndexDocument {
  first_seen_utc?: string;
  sha256_hash?: string;
  md5_hash?: string;
  sha1_hash?: string;
  reporter?: string;
  file_name?: string;
  file_type_guess?: string;
  mime_type?: string;
  signature?: string;
  clamav?: string;
  vtpercent?: string;
  imphash?: string;
  ssdeep?: string;
  tlsh?: string;
  source: 'malwarebazaar_api' | 'malwarebazaar_full_csv' | 'custom';
  updated_at: string;
  name: string;
  enabled: boolean;
  severity: string;
  tags: string[];
  content: string;
  validation: RuleValidation;
}

export interface HashRuleSummary {
  id: string;
  name: string;
  source: string;
  enabled: boolean;
  severity: string;
  tags: string[];
  updatedAt: string;
  validation: RuleValidation;
  sha256_hash?: string;
  md5_hash?: string;
  sha1_hash?: string;
  file_name?: string;
  signature?: string;
  reporter?: string;
}

export interface HashSearchResult {
  rules: HashRuleSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface BundleCandidateFilters {
  source?: HashIndexDocument['source'];
  enabled?: boolean;
}

export interface BulkHashUpsertItem {
  id: string;
  doc: Partial<HashIndexDocument>;
  upsert: HashIndexDocument;
}

export interface BulkHashUpsertResult {
  created: number;
  updated: number;
  noop: number;
  failed: number;
}

export interface BundleEligibilityCandidate {
  enabled: boolean;
  severity: unknown;
  source?: unknown;
  validation?: {
    status?: unknown;
  };
}

let hashesIndexReady = false;
let hashesIndexEnsureInFlight: Promise<void> | null = null;

function nowIso(): string {
  return new Date().toISOString();
}

function lowerOrUndefined(raw: unknown): string | undefined {
  const value = String(raw ?? '').trim().toLowerCase();
  return value.length > 0 ? value : undefined;
}

function normalizeTags(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return input
    .map((entry) => String(entry).trim())
    .filter((entry) => entry.length > 0)
    .slice(0, 32);
}

function normalizeValidation(input: unknown): RuleValidation {
  if (!input || typeof input !== 'object') {
    return {
      status: 'valid',
      errors: [],
      warnings: [],
      checkedAt: nowIso()
    };
  }

  const asObj = input as Record<string, unknown>;
  return {
    status: asObj.status === 'invalid' ? 'invalid' : 'valid',
    errors: Array.isArray(asObj.errors) ? asObj.errors.map((entry) => String(entry)) : [],
    warnings: Array.isArray(asObj.warnings) ? asObj.warnings.map((entry) => String(entry)) : [],
    checkedAt: String(asObj.checkedAt ?? nowIso())
  };
}

function mapHit(hit: any): HashRuleSummary | null {
  const source = hit?._source;
  if (!source) {
    return null;
  }

  const id = String(hit?._id ?? '').trim();
  if (!id) {
    return null;
  }

  return {
    id,
    name: String(source.name ?? source.sha256_hash ?? id),
    source: String(source.source ?? 'custom'),
    enabled: Boolean(source.enabled),
    severity: String(source.severity ?? 'medium'),
    tags: normalizeTags(source.tags),
    updatedAt: String(source.updated_at ?? nowIso()),
    validation: normalizeValidation(source.validation),
    sha256_hash: source.sha256_hash ? String(source.sha256_hash) : undefined,
    md5_hash: source.md5_hash ? String(source.md5_hash) : undefined,
    sha1_hash: source.sha1_hash ? String(source.sha1_hash) : undefined,
    file_name: source.file_name ? String(source.file_name) : undefined,
    signature: source.signature ? String(source.signature) : undefined,
    reporter: source.reporter ? String(source.reporter) : undefined
  };
}

function escapedWildcard(raw: string): string {
  return raw.replace(/[\\*?]/g, '').trim().toLowerCase();
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

function hashesIndexDefinition() {
  return {
    mappings: {
      properties: {
        first_seen_utc: { type: 'date' },
        sha256_hash: { type: 'keyword' },
        md5_hash: { type: 'keyword' },
        sha1_hash: { type: 'keyword' },
        reporter: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 256 } }
        },
        file_name: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 512 } }
        },
        file_type_guess: { type: 'keyword' },
        mime_type: { type: 'keyword' },
        signature: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 256 } }
        },
        clamav: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 512 } }
        },
        vtpercent: { type: 'keyword' },
        imphash: { type: 'keyword' },
        ssdeep: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 512 } }
        },
        tlsh: { type: 'keyword' },
        source: { type: 'keyword' },
        updated_at: { type: 'date' },
        name: {
          type: 'text',
          fields: { keyword: { type: 'keyword', ignore_above: 256 } }
        },
        enabled: { type: 'boolean' },
        severity: { type: 'keyword' },
        tags: { type: 'keyword' },
        content: { type: 'text' },
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

export function malwareBazaarDocId(sha256: string): string {
  return sha256.toLowerCase();
}

export function customDocId(content: string): string {
  const digest = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  return `custom-${digest.slice(0, 40)}`;
}

export async function ensureHashesIndex(client: any): Promise<void> {
  if (hashesIndexReady) {
    return;
  }

  if (!hashesIndexEnsureInFlight) {
    hashesIndexEnsureInFlight = (async () => {
      const existsResponse = await client.indices.exists({ index: HASHES_INDEX_NAME });
      if (indexExistsResponseToBoolean(existsResponse)) {
        hashesIndexReady = true;
        return;
      }

      try {
        await client.indices.create({
          index: HASHES_INDEX_NAME,
          body: hashesIndexDefinition()
        });
      } catch (err: any) {
        if (!isAlreadyExistsError(err)) {
          throw err;
        }
      }

      hashesIndexReady = true;
    })().finally(() => {
      hashesIndexEnsureInFlight = null;
    });
  }

  return hashesIndexEnsureInFlight;
}

export async function upsertHashDocument(
  client: any,
  id: string,
  doc: HashIndexDocument,
  options?: { refresh?: false | 'wait_for' | true }
): Promise<'created' | 'updated' | 'noop'> {
  await ensureHashesIndex(client);
  const response = await client.update({
    index: HASHES_INDEX_NAME,
    id,
    refresh: options?.refresh ?? 'wait_for',
    body: {
      doc,
      doc_as_upsert: true
    }
  });

  const result = String(response?.body?.result ?? 'updated');
  if (result === 'created' || result === 'updated' || result === 'noop') {
    return result;
  }
  return 'updated';
}

export async function bulkUpsertHashDocuments(
  client: any,
  items: BulkHashUpsertItem[],
  options?: { refresh?: false | 'wait_for' | true }
): Promise<BulkHashUpsertResult> {
  await ensureHashesIndex(client);

  if (items.length === 0) {
    return { created: 0, updated: 0, noop: 0, failed: 0 };
  }

  const body: any[] = [];
  for (const item of items) {
    body.push({ update: { _index: HASHES_INDEX_NAME, _id: item.id } });
    body.push({
      doc: item.doc,
      upsert: item.upsert,
      doc_as_upsert: false
    });
  }

  const response = await client.bulk({
    refresh: options?.refresh ?? false,
    body
  });

  const bulkItems = Array.isArray(response?.body?.items) ? response.body.items : [];
  let created = 0;
  let updated = 0;
  let noop = 0;
  let failed = 0;

  for (const row of bulkItems) {
    const update = row?.update;
    const status = Number(update?.status ?? 0);
    const hasError = Boolean(update?.error) || status >= 400;
    if (hasError) {
      failed += 1;
      continue;
    }

    const result = String(update?.result ?? 'updated');
    if (result === 'created') {
      created += 1;
    } else if (result === 'noop') {
      noop += 1;
    } else {
      updated += 1;
    }
  }

  return { created, updated, noop, failed };
}

export async function getHashDocument(client: any, id: string): Promise<HashIndexDocument | null> {
  await ensureHashesIndex(client);
  try {
    const response = await client.get({ index: HASHES_INDEX_NAME, id });
    if (!response?.body?._source) {
      return null;
    }
    const source = response.body._source as HashIndexDocument;
    return {
      ...source,
      sha256_hash: lowerOrUndefined(source.sha256_hash),
      md5_hash: lowerOrUndefined(source.md5_hash),
      sha1_hash: lowerOrUndefined(source.sha1_hash),
      tags: normalizeTags(source.tags),
      validation: normalizeValidation(source.validation),
      updated_at: String(source.updated_at ?? nowIso()),
      source: (source.source as HashIndexDocument['source']) ?? 'custom',
      name: String(source.name ?? id),
      enabled: Boolean(source.enabled),
      severity: String(source.severity ?? 'medium'),
      content: String(source.content ?? '')
    };
  } catch (_err) {
    return null;
  }
}

export async function deleteHashDocument(client: any, id: string): Promise<boolean> {
  await ensureHashesIndex(client);
  try {
    await client.delete({
      index: HASHES_INDEX_NAME,
      id,
      refresh: 'wait_for'
    });
    return true;
  } catch (_err) {
    return false;
  }
}

export async function listHashRulesIndexed(
  client: any,
  input: { q?: string; page?: number; pageSize?: number }
): Promise<HashSearchResult> {
  await ensureHashesIndex(client);

  const pageSize = Math.max(1, Math.min(500, Number(input.pageSize ?? 20)));
  const page = Math.max(1, Number(input.page ?? 1));
  const from = (page - 1) * pageSize;
  const queryText = String(input.q ?? '').trim();

  const should: any[] = [];
  if (queryText.length > 0) {
    should.push({
      multi_match: {
        query: queryText,
        fields: [
          'sha256_hash^8',
          'md5_hash^7',
          'sha1_hash^7',
          'file_name^5',
          'signature^4',
          'name^4',
          'reporter^3',
          'tags^3',
          'content^2',
          'source'
        ],
        type: 'best_fields',
        operator: 'and'
      }
    });

    const wildcard = escapedWildcard(queryText);
    if (wildcard.length >= 3) {
      should.push({ wildcard: { sha256_hash: `*${wildcard}*` } });
      should.push({ wildcard: { md5_hash: `*${wildcard}*` } });
      should.push({ wildcard: { sha1_hash: `*${wildcard}*` } });
      should.push({ wildcard: { 'file_name.keyword': `*${wildcard}*` } });
      should.push({ wildcard: { 'signature.keyword': `*${wildcard}*` } });
      should.push({ wildcard: { 'reporter.keyword': `*${wildcard}*` } });
    }
  }

  const body: Record<string, unknown> = {
    from,
    size: pageSize,
    sort: [{ updated_at: { order: 'desc' } }],
    track_total_hits: true
  };

  if (should.length > 0) {
    body.query = {
      bool: {
        should,
        minimum_should_match: 1
      }
    };
  } else {
    body.query = { match_all: {} };
  }

  const response = await client.search({
    index: HASHES_INDEX_NAME,
    allow_no_indices: true,
    ignore_unavailable: true,
    body
  });

  const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
  const rules = hits.map((hit: any) => mapHit(hit)).filter((entry: HashRuleSummary | null): entry is HashRuleSummary => entry !== null);

  const totalRaw = response?.body?.hits?.total;
  const total = typeof totalRaw?.value === 'number' ? totalRaw.value : typeof totalRaw === 'number' ? totalRaw : rules.length;

  return {
    rules,
    page,
    pageSize,
    total
  };
}

export async function listBundleCandidates(
  client: any,
  filters?: BundleCandidateFilters
): Promise<HashRuleSummary[]> {
  await ensureHashesIndex(client);
  const pageSize = 3000;
  const rules: HashRuleSummary[] = [];
  let searchAfter: unknown[] | undefined;

  const must: Array<Record<string, unknown>> = [];
  if (typeof filters?.enabled === 'boolean') {
    must.push({ term: { enabled: filters.enabled } });
  }
  if (filters?.source) {
    must.push({ term: { source: filters.source } });
  }

  while (true) {
    const response = await client.search({
      index: HASHES_INDEX_NAME,
      size: pageSize,
      allow_no_indices: true,
      ignore_unavailable: true,
      body: {
        query: must.length > 0 ? { bool: { must } } : { match_all: {} },
        sort: [{ updated_at: { order: 'desc' } }, { _id: { order: 'desc' } }],
        ...(searchAfter ? { search_after: searchAfter } : {})
      }
    });

    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    if (hits.length === 0) {
      break;
    }

    for (const hit of hits) {
      const mapped = mapHit(hit);
      if (mapped) {
        rules.push(mapped);
      }
    }

    const lastHit = hits[hits.length - 1];
    const lastSort = Array.isArray(lastHit?.sort) ? lastHit.sort : undefined;
    if (!lastSort || lastSort.length === 0 || hits.length < pageSize) {
      break;
    }
    searchAfter = lastSort;
  }

  return rules;
}

function normalizeBundleSeverity(raw: unknown): 'critical' | 'high' | 'medium' | 'low' {
  const value = String(raw ?? '').trim().toLowerCase();
  if (value === 'critical' || value === 'crit') {
    return 'critical';
  }
  if (value === 'high') {
    return 'high';
  }
  if (value === 'low') {
    return 'low';
  }
  return 'medium';
}

export function isEligibleHashBundleRule(rule: BundleEligibilityCandidate): boolean {
  if (!rule.enabled) {
    return false;
  }

  if (String(rule.validation?.status ?? '').toLowerCase() !== 'valid') {
    return false;
  }

  return normalizeBundleSeverity(rule.severity) === 'critical';
}
