declare const require: any;

const crypto = require('crypto');
const BufferCtor = (globalThis as any).Buffer;

import {
  HASHES_INDEX_NAME,
  bulkUpsertHashDocuments,
  customDocId,
  deleteHashDocument,
  ensureHashesIndex,
  getHashDocument,
  isEligibleHashBundleRule,
  listHashRulesIndexed,
  malwareBazaarDocId,
  upsertHashDocument,
  type HashIndexDocument
} from '../lib/hashes_index';
import {
  fetchMalwareBazaarHashes,
  syncMalwareBazaarDailyFullCsv,
  type MalwareBazaarSample
} from '../lib/malwarebazaar';
import { getMalwareBazaarApiKey, getMalwareBazaarApiKeyStatus, setMalwareBazaarApiKey } from '../lib/secret_store';
import { getSigningPrivateKey } from '../lib/signing_keys';
import { getMalwareBazaarSyncState, updateMalwareBazaarSyncState } from '../lib/upstream_sync_store';
import { validateHashContent } from '../lib/hashes_store';

const { schema } = require('@osd/config-schema');

type MalwareBazaarSyncStatus = 'idle' | 'processing' | 'completed' | 'failed';
type MalwareBazaarSyncPhase =
  | 'idle'
  | 'requesting_export'
  | 'preparing_download'
  | 'downloading'
  | 'importing'
  | 'completed'
  | 'failed';
type MalwareBazaarSyncMode = 'malwarebazaar_api' | 'daily_full_csv';

interface MalwareBazaarSyncMetadata {
  status: MalwareBazaarSyncStatus;
  phase?: MalwareBazaarSyncPhase;
  started_at?: string;
  completed_at?: string;
  synced_at?: string;
  query_mode?: string;
  upstream_records?: number;
  new_hashes?: number;
  total_hashes?: number;
  attempted?: number;
  imported?: number;
  unchanged?: number;
  load_failures?: number;
  mode?: MalwareBazaarSyncMode;
  message?: string;
  errors?: string[];
}

interface BundleRuleEntry {
  id: string;
  filename: string;
  content: string;
  sha256: string;
  enabled: boolean;
  source: string;
  updatedAt: string;
}

interface SignedBundleResponse {
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

type Severity = 'critical' | 'high' | 'medium' | 'low';

const MALWAREBAZAAR_DEFAULT_RECENT_LIMIT = 100;
const HASH_BUNDLE_CHUNK_SIZE = 5000;
const HASH_BUNDLE_SCAN_PAGE_SIZE = 5000;

interface DailyHashBundleSnapshot {
  dateVersion: string;
  bundleVersion: number;
  generatedAt: string;
  rules: BundleRuleEntry[];
  activeChecksums: string[];
  totalCriticalHashes: number;
}

let dailyHashBundleSnapshot: DailyHashBundleSnapshot | null = null;
let dailyHashBundleBuildInFlight: Promise<DailyHashBundleSnapshot> | null = null;

let malwareBazaarSyncInFlight = false;
let malwareBazaarSyncMetadata: MalwareBazaarSyncMetadata = { status: 'idle' };

function nowIso(): string {
  return new Date().toISOString();
}

function todayDateVersion(): string {
  return new Date().toISOString().slice(0, 10);
}

function dateVersionToBundleVersion(dateVersion: string): number {
  const normalized = String(dateVersion).replace(/-/g, '');
  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`invalid date version ${dateVersion}`);
  }
  return parsed;
}

function formatMb(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function scopedOsClient(ctx: any): any | null {
  if (typeof ctx?.core?.opensearch?.client?.asInternalUser?.search === 'function') {
    return ctx.core.opensearch.client.asInternalUser;
  }
  if (typeof ctx?.opensearch?.client?.asInternalUser?.search === 'function') {
    return ctx.opensearch.client.asInternalUser;
  }
  if (typeof ctx?.core?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.core.opensearch.client.asCurrentUser;
  }
  if (typeof ctx?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.opensearch.client.asCurrentUser;
  }
  return null;
}

function persistedMalwareBazaarSnapshot(): MalwareBazaarSyncMetadata {
  const persisted = getMalwareBazaarSyncState();
  if (!persisted.last_attempted_at) {
    return { status: 'idle' };
  }

  const persistedStatus = !malwareBazaarSyncInFlight && persisted.status === 'processing'
    ? persisted.last_error
      ? 'failed'
      : persisted.last_completed_at
        ? 'completed'
        : 'idle'
    : persisted.status;
  const persistedPhase = !malwareBazaarSyncInFlight && persisted.status === 'processing'
    ? persisted.last_error
      ? 'failed'
      : persisted.last_completed_at
        ? 'completed'
        : 'idle'
    : persisted.phase;
  const failed = Boolean(persisted.last_error);
  return {
    status: failed ? 'failed' : persistedStatus ?? 'completed',
    phase: failed ? 'failed' : persistedPhase ?? 'completed',
    started_at: persisted.last_attempted_at,
    completed_at: persisted.last_completed_at,
    synced_at: persisted.last_successful_sync_at,
    query_mode: persisted.last_query_mode,
    upstream_records: persisted.last_upstream_records,
    new_hashes: persisted.last_new_hashes,
    total_hashes: persisted.last_total_hashes,
    attempted: persisted.last_upstream_records,
    imported: persisted.imported,
    unchanged: persisted.unchanged,
    load_failures: persisted.load_failures,
    mode: persisted.last_query_mode === 'daily_full_csv_export' ? 'daily_full_csv' : 'malwarebazaar_api',
    message: persisted.message,
    errors: failed && persisted.last_error ? [persisted.last_error] : []
  };
}

function malwareBazaarSnapshot(): MalwareBazaarSyncMetadata {
  if (malwareBazaarSyncMetadata.status === 'idle') {
    return persistedMalwareBazaarSnapshot();
  }

  return {
    ...malwareBazaarSyncMetadata,
    errors: [...(malwareBazaarSyncMetadata.errors ?? [])]
  };
}

function malwareBazaarStatusBody(): Record<string, unknown> {
  const runtime = malwareBazaarSnapshot();
  const sync = getMalwareBazaarSyncState();
  const secretStatus = getMalwareBazaarApiKeyStatus();
  return {
    status: runtime.status,
    phase: runtime.phase,
    mode: runtime.mode,
    message: runtime.message,
    attempted: runtime.attempted,
    imported: runtime.imported,
    unchanged: runtime.unchanged,
    load_failures: runtime.load_failures,
    api_key_configured: secretStatus.configured,
    api_key_updated_at: secretStatus.updated_at ?? sync.api_key_updated_at,
    last_attempted_at: runtime.started_at ?? sync.last_attempted_at,
    last_completed_at: runtime.completed_at ?? sync.last_completed_at,
    last_successful_sync_at: runtime.synced_at ?? sync.last_successful_sync_at,
    last_cursor_seen_at: sync.last_cursor_seen_at,
    last_query_mode: runtime.query_mode ?? sync.last_query_mode,
    last_upstream_records: runtime.upstream_records ?? sync.last_upstream_records,
    last_new_hashes: runtime.new_hashes ?? sync.last_new_hashes,
    last_total_hashes: runtime.total_hashes ?? sync.last_total_hashes,
    last_error: runtime.status === 'failed' ? runtime.errors?.[0] : sync.last_error,
    pull_limit: MALWAREBAZAAR_DEFAULT_RECENT_LIMIT,
    backing_index: HASHES_INDEX_NAME
  };
}

function syncAlreadyRunningResponse(res: any, requestedMode: MalwareBazaarSyncMode) {
  const snapshot = malwareBazaarSnapshot();
  return res.customError({
    statusCode: 409,
    body: {
      message: 'A MalwareBazaar hash sync is already running.',
      started: false,
      requested_mode: requestedMode,
      running_mode: snapshot.mode,
      query_mode: snapshot.query_mode,
      attempted: snapshot.attempted ?? 0,
      upstream_records: snapshot.upstream_records ?? 0,
      new_hashes: snapshot.new_hashes ?? 0,
      total_hashes: snapshot.total_hashes ?? 0,
      imported: snapshot.imported ?? 0,
      unchanged: snapshot.unchanged ?? 0,
      load_failures: snapshot.load_failures ?? 0,
      errors: snapshot.errors ?? [],
      metadata: snapshot
    }
  });
}

function cleanString(raw: unknown): string | undefined {
  const value = String(raw ?? '').trim();
  if (!value || value.toLowerCase() === 'n/a' || value.toLowerCase() === 'none' || value === '-') {
    return undefined;
  }
  return value;
}

function normalizeHash(raw: unknown, length: number): string | undefined {
  const value = String(raw ?? '').trim().toLowerCase();
  const re = new RegExp(`^[a-f0-9]{${length}}$`);
  return re.test(value) ? value : undefined;
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    default:
      return 1;
  }
}

function parseVtPercent(raw: unknown): number | undefined {
  const cleaned = String(raw ?? '').trim().replace('%', '');
  if (!cleaned) {
    return undefined;
  }

  const numerator = cleaned.split('/')[0];
  const value = Number.parseFloat(numerator);
  if (!Number.isFinite(value)) {
    return undefined;
  }
  return Math.max(0, Math.min(100, value));
}

function deriveMalwareBazaarSeverity(sample: MalwareBazaarSample): Severity {
  let derived: Severity = 'low';
  const vtpercent = parseVtPercent(sample.vtpercent);
  if (typeof vtpercent === 'number') {
    if (vtpercent >= 60) {
      derived = 'critical';
    } else if (vtpercent >= 25) {
      derived = 'high';
    } else if (vtpercent >= 5) {
      derived = 'medium';
    }
  }

  const signature = String(sample.signature ?? '').toLowerCase();
  const criticalKeywords = ['ransom', 'wiper', 'rootkit'];
  const highKeywords = ['stealer', 'banker', 'backdoor', 'botnet', 'worm', 'trojan'];

  if (criticalKeywords.some((keyword) => signature.includes(keyword))) {
    return severityRank(derived) >= severityRank('critical') ? derived : 'critical';
  }
  if (highKeywords.some((keyword) => signature.includes(keyword))) {
    return severityRank(derived) >= severityRank('high') ? derived : 'high';
  }

  return derived;
}

function toDocument(input: {
  sha256: string;
  source: HashIndexDocument['source'];
  sample: MalwareBazaarSample;
}): HashIndexDocument {
  const computedTags = [
    'malwarebazaar',
    input.source === 'malwarebazaar_full_csv' ? 'full-csv' : 'api-synced',
    ...(Array.isArray(input.sample.tags) ? input.sample.tags : [])
  ]
    .map((entry) => String(entry).trim())
    .filter((entry) => entry.length > 0);

  const tags = Array.from(new Set(computedTags)).slice(0, 32);
  const signature = cleanString(input.sample.signature);

  return {
    first_seen_utc: cleanString(input.sample.first_seen),
    sha256_hash: input.sha256,
    md5_hash: normalizeHash(input.sample.md5_hash, 32),
    sha1_hash: normalizeHash(input.sample.sha1_hash, 40),
    reporter: cleanString(input.sample.reporter),
    file_name: cleanString(input.sample.file_name),
    file_type_guess: cleanString(input.sample.file_type_guess),
    mime_type: cleanString(input.sample.mime_type),
    signature,
    clamav: cleanString(input.sample.clamav),
    vtpercent: cleanString(input.sample.vtpercent),
    imphash: normalizeHash(input.sample.imphash, 32),
    ssdeep: cleanString(input.sample.ssdeep),
    tlsh: cleanString(input.sample.tlsh),
    source: input.source,
    updated_at: nowIso(),
    name: signature ? `MalwareBazaar ${signature}` : `MalwareBazaar SHA256 ${input.sha256.slice(0, 12)}`,
    enabled: true,
    severity: deriveMalwareBazaarSeverity(input.sample),
    tags,
    content: `sha256:${input.sha256}`,
    validation: {
      status: 'valid',
      errors: [],
      warnings: [],
      checkedAt: nowIso()
    }
  };
}

function toUpdateDocument(doc: HashIndexDocument): Partial<HashIndexDocument> {
  // Keep operator-managed fields (enabled/tags) untouched for existing docs.
  return {
    first_seen_utc: doc.first_seen_utc,
    sha256_hash: doc.sha256_hash,
    md5_hash: doc.md5_hash,
    sha1_hash: doc.sha1_hash,
    reporter: doc.reporter,
    file_name: doc.file_name,
    file_type_guess: doc.file_type_guess,
    mime_type: doc.mime_type,
    signature: doc.signature,
    clamav: doc.clamav,
    vtpercent: doc.vtpercent,
    imphash: doc.imphash,
    ssdeep: doc.ssdeep,
    tlsh: doc.tlsh,
    source: doc.source,
    updated_at: doc.updated_at,
    name: doc.name,
    severity: doc.severity,
    content: doc.content,
    validation: doc.validation
  };
}

async function countIndexedHashes(client: any): Promise<number> {
  await ensureHashesIndex(client);
  const response = await client.count({
    index: HASHES_INDEX_NAME,
    body: { query: { match_all: {} } }
  });
  return Number(response?.body?.count ?? 0);
}

async function ingestMalwareBazaarRows(input: {
  client: any;
  samples: MalwareBazaarSample[];
  mode: MalwareBazaarSyncMode;
  includeTotalHashes?: boolean;
}): Promise<{ attempted: number; imported: number; unchanged: number; load_failures: number; new_hashes: number; total_hashes?: number }> {
  const source: HashIndexDocument['source'] = input.mode === 'daily_full_csv' ? 'malwarebazaar_full_csv' : 'malwarebazaar_api';

  const bulkItems: Array<{ id: string; doc: Partial<HashIndexDocument>; upsert: HashIndexDocument }> = [];
  let loadFailures = 0;

  for (const sample of input.samples) {
    const sha256 = normalizeHash(sample.sha256_hash, 64);
    if (!sha256) {
      loadFailures += 1;
      continue;
    }

    const id = malwareBazaarDocId(sha256);
    const fullDoc = toDocument({ sha256, source, sample });
    bulkItems.push({
      id,
      doc: toUpdateDocument(fullDoc),
      upsert: fullDoc
    });
  }

  const bulkResult = await bulkUpsertHashDocuments(input.client, bulkItems, { refresh: false });
  const imported = bulkResult.created + bulkResult.updated;
  const unchanged = bulkResult.noop;
  loadFailures += bulkResult.failed;
  const totalHashes = input.includeTotalHashes ? await countIndexedHashes(input.client) : undefined;

  return {
    attempted: input.samples.length,
    imported,
    unchanged,
    load_failures: loadFailures,
    new_hashes: bulkResult.created,
    total_hashes: totalHashes
  };
}

async function performMalwareBazaarSync(client: any): Promise<Record<string, unknown>> {
  const apiKey = getMalwareBazaarApiKey();
  if (!apiKey) {
    throw new Error('Configure a MalwareBazaar API key before syncing hashes.');
  }

  const startedAt = nowIso();
  malwareBazaarSyncMetadata = {
    status: 'processing',
    phase: 'downloading',
    started_at: startedAt,
    mode: 'malwarebazaar_api',
    message: 'Downloading malware hashes from MalwareBazaar API.',
    attempted: 0,
    imported: 0,
    unchanged: 0,
    load_failures: 0,
    errors: []
  };
  updateMalwareBazaarSyncState({
    status: 'processing',
    phase: 'downloading',
    message: malwareBazaarSyncMetadata.message,
    imported: 0,
    unchanged: 0,
    load_failures: 0,
    last_attempted_at: startedAt,
    last_error: undefined
  });

  const feed = await fetchMalwareBazaarHashes({
    apiKey,
    recentLimit: MALWAREBAZAAR_DEFAULT_RECENT_LIMIT
  });

  malwareBazaarSyncMetadata = {
    ...malwareBazaarSyncMetadata,
    phase: 'importing',
    query_mode: feed.query_mode,
    upstream_records: feed.samples.length,
    attempted: feed.samples.length,
    message: `Importing ${feed.samples.length} hashes into ${HASHES_INDEX_NAME} (${feed.query_mode}).`
  };

  updateMalwareBazaarSyncState({
    status: 'processing',
    phase: 'importing',
    message: malwareBazaarSyncMetadata.message,
    last_query_mode: feed.query_mode,
    last_upstream_records: feed.samples.length
  });

  const counters = await ingestMalwareBazaarRows({
    client,
    samples: feed.samples,
    mode: 'malwarebazaar_api',
    includeTotalHashes: true
  });

  const completedAt = nowIso();
  malwareBazaarSyncMetadata = {
    status: 'completed',
    phase: 'completed',
    started_at: startedAt,
    completed_at: completedAt,
    synced_at: completedAt,
    mode: 'malwarebazaar_api',
    query_mode: feed.query_mode,
    upstream_records: feed.samples.length,
    attempted: counters.attempted,
    new_hashes: counters.new_hashes,
    total_hashes: counters.total_hashes,
    imported: counters.imported,
    unchanged: counters.unchanged,
    load_failures: counters.load_failures,
    message: 'MalwareBazaar hash API sync completed.',
    errors: []
  };

  updateMalwareBazaarSyncState({
    status: 'completed',
    phase: 'completed',
    message: malwareBazaarSyncMetadata.message,
    last_attempted_at: startedAt,
    last_completed_at: completedAt,
    last_successful_sync_at: completedAt,
    last_cursor_seen_at: feed.cursor_seen_at,
    last_query_mode: feed.query_mode,
    last_upstream_records: feed.samples.length,
    last_new_hashes: counters.new_hashes,
    last_total_hashes: counters.total_hashes,
    imported: counters.imported,
    unchanged: counters.unchanged,
    load_failures: counters.load_failures,
    last_error: undefined
  });

  await prebuildDailyHashBundleSnapshotBestEffort(client, { forceRebuild: true });

  return {
    message: 'MalwareBazaar hash sync completed.',
    mode: 'malwarebazaar_api',
    query_mode: feed.query_mode,
    upstream_records: feed.samples.length,
    attempted: counters.attempted,
    new_hashes: counters.new_hashes,
    total_hashes: counters.total_hashes,
    imported: counters.imported,
    unchanged: counters.unchanged,
    load_failures: counters.load_failures,
    errors: [],
    status: malwareBazaarStatusBody()
  };
}

async function performMalwareBazaarDailyFullSync(client: any): Promise<Record<string, unknown>> {
  const apiKey = getMalwareBazaarApiKey() ?? undefined;

  const startedAt = nowIso();

  malwareBazaarSyncMetadata = {
    status: 'processing',
    phase: 'requesting_export',
    started_at: startedAt,
    mode: 'daily_full_csv',
    query_mode: 'daily_full_csv_export',
    message: 'Requesting MalwareBazaar daily full export.',
    attempted: 0,
    imported: 0,
    unchanged: 0,
    load_failures: 0,
    errors: []
  };

  updateMalwareBazaarSyncState({
    status: 'processing',
    phase: 'requesting_export',
    message: malwareBazaarSyncMetadata.message,
    last_query_mode: 'daily_full_csv_export',
    imported: 0,
    unchanged: 0,
    load_failures: 0,
    last_attempted_at: startedAt,
    last_error: undefined
  });

  const counters = {
    attempted: 0,
    imported: 0,
    unchanged: 0,
    load_failures: 0,
    new_hashes: 0,
    total_hashes: 0
  };

  const feed = await syncMalwareBazaarDailyFullCsv({
    apiKey,
    batchSize: 5000,
    onPhase: (phaseMessage) => {
      const lower = String(phaseMessage).toLowerCase();
      const phase: MalwareBazaarSyncPhase =
        lower.includes('request') ? 'requesting_export' : lower.includes('prepar') ? 'preparing_download' : 'downloading';
      malwareBazaarSyncMetadata = {
        ...malwareBazaarSyncMetadata,
        status: 'processing',
        phase,
        message: phaseMessage
      };
      updateMalwareBazaarSyncState({
        status: 'processing',
        phase,
        message: phaseMessage
      });
    },
    onProgress: (downloadedBytes, totalBytes) => {
      const progress = totalBytes
        ? `Downloading ${formatMb(downloadedBytes)} / ${formatMb(totalBytes)}`
        : `Downloading ${formatMb(downloadedBytes)}`;
      malwareBazaarSyncMetadata = {
        ...malwareBazaarSyncMetadata,
        status: 'processing',
        phase: 'downloading',
        message: progress
      };
      updateMalwareBazaarSyncState({
        status: 'processing',
        phase: 'downloading',
        message: progress
      });
    },
    onBatch: async (rows: MalwareBazaarSample[]) => {
      if (rows.length === 0) {
        return;
      }

      const batchResult = await ingestMalwareBazaarRows({
        client,
        samples: rows,
        mode: 'daily_full_csv',
        includeTotalHashes: false
      });

      counters.attempted += batchResult.attempted;
      counters.imported += batchResult.imported;
      counters.unchanged += batchResult.unchanged;
      counters.load_failures += batchResult.load_failures;
      counters.new_hashes += batchResult.new_hashes;

      malwareBazaarSyncMetadata = {
        ...malwareBazaarSyncMetadata,
        status: 'processing',
        phase: 'importing',
        attempted: counters.attempted,
        imported: counters.imported,
        unchanged: counters.unchanged,
        load_failures: counters.load_failures,
        new_hashes: counters.new_hashes,
        message: `Importing daily export hashes (${counters.attempted} processed).`
      };
      updateMalwareBazaarSyncState({
        status: 'processing',
        phase: 'importing',
        message: malwareBazaarSyncMetadata.message,
        imported: counters.imported,
        unchanged: counters.unchanged,
        load_failures: counters.load_failures
      });
    }
  });

  await client.indices.refresh({ index: HASHES_INDEX_NAME });
  counters.total_hashes = await countIndexedHashes(client);

  malwareBazaarSyncMetadata = {
    ...malwareBazaarSyncMetadata,
    phase: 'importing',
    query_mode: feed.query_mode,
    upstream_records: feed.upstream_records,
    attempted: counters.attempted,
    message: `Importing ${feed.upstream_records} hashes into ${HASHES_INDEX_NAME} (${feed.query_mode}).`
  };

  updateMalwareBazaarSyncState({
    status: 'processing',
    phase: 'importing',
    message: malwareBazaarSyncMetadata.message,
    last_query_mode: feed.query_mode,
    last_upstream_records: feed.upstream_records
  });

  const completedAt = nowIso();
  malwareBazaarSyncMetadata = {
    status: 'completed',
    phase: 'completed',
    started_at: startedAt,
    completed_at: completedAt,
    synced_at: completedAt,
    mode: 'daily_full_csv',
    query_mode: feed.query_mode,
    upstream_records: feed.upstream_records,
    attempted: counters.attempted,
    new_hashes: counters.new_hashes,
    total_hashes: counters.total_hashes,
    imported: counters.imported,
    unchanged: counters.unchanged,
    load_failures: counters.load_failures,
    message: 'MalwareBazaar daily full CSV sync completed.',
    errors: []
  };

  updateMalwareBazaarSyncState({
    status: 'completed',
    phase: 'completed',
    message: malwareBazaarSyncMetadata.message,
    last_attempted_at: startedAt,
    last_completed_at: completedAt,
    last_successful_sync_at: completedAt,
    last_query_mode: feed.query_mode,
    last_upstream_records: feed.upstream_records,
    last_new_hashes: counters.new_hashes,
    last_total_hashes: counters.total_hashes,
    imported: counters.imported,
    unchanged: counters.unchanged,
    load_failures: counters.load_failures,
    last_error: undefined
  });

  await prebuildDailyHashBundleSnapshotBestEffort(client, { forceRebuild: true });

  return {
    message: 'MalwareBazaar daily full CSV hash sync completed.',
    mode: 'daily_full_csv',
    query_mode: feed.query_mode,
    upstream_records: feed.upstream_records,
    attempted: counters.attempted,
    new_hashes: counters.new_hashes,
    total_hashes: counters.total_hashes,
    imported: counters.imported,
    unchanged: counters.unchanged,
    load_failures: counters.load_failures,
    errors: [],
    status: malwareBazaarStatusBody()
  };
}

function parseHashLine(lineRaw: string): { sha256?: string; md5?: string; sha1?: string } | null {
  const line = lineRaw.trim().toLowerCase();
  if (!line || line.startsWith('#')) {
    return null;
  }

  const sha256 = line.match(/^sha256:([a-f0-9]{64})$/)?.[1] ?? line.match(/^([a-f0-9]{64})$/)?.[1];
  if (sha256) {
    return { sha256 };
  }

  const md5 = line.match(/^md5:([a-f0-9]{32})$/)?.[1] ?? line.match(/^([a-f0-9]{32})$/)?.[1];
  if (md5) {
    return { md5 };
  }

  const sha1 = line.match(/^sha1:([a-f0-9]{40})$/)?.[1] ?? line.match(/^([a-f0-9]{40})$/)?.[1];
  if (sha1) {
    return { sha1 };
  }

  return null;
}

function hashYamlChunkContent(items: Array<{ sha256_hash: string; name: string; severity: string; source: string }>): string {
  if (items.length === 0) {
    return 'hashes: []\n';
  }

  const lines: string[] = ['hashes:'];
  for (const item of items) {
    const escapedName = item.name.replace(/'/g, "''");
    const safeName = /[:#\[\]{},|>&*!?'"\\]/.test(item.name) ? `'${escapedName}'` : item.name;
    lines.push(`  - sha256: ${item.sha256_hash}`);
    lines.push(`    name: ${safeName}`);
    lines.push(`    severity: ${item.severity}`);
    lines.push(`    source: ${item.source}`);
  }

  return `${lines.join('\n')}\n`;
}

async function buildDailyHashBundleSnapshot(client: any): Promise<DailyHashBundleSnapshot> {
  await ensureHashesIndex(client);

  const dateVersion = todayDateVersion();
  const generatedAt = `${dateVersion}T00:00:00.000Z`;
  const bundleVersion = dateVersionToBundleVersion(dateVersion);
  const rules: BundleRuleEntry[] = [];
  const activeChecksums: string[] = [];

  let searchAfter: unknown[] | undefined;
  let chunkRows: Array<{ sha256_hash: string; name: string; severity: string; source: string }> = [];
  let chunkSeq = 0;
  let totalCriticalHashes = 0;

  const flushChunk = () => {
    if (chunkRows.length === 0) {
      return;
    }

    chunkSeq += 1;
    const chunkID = `critical-hashes-${dateVersion}-${String(chunkSeq).padStart(5, '0')}`;
    const content = hashYamlChunkContent(chunkRows);
    const sha256 = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    const entry: BundleRuleEntry = {
      id: chunkID,
      filename: `${chunkID}.yaml`,
      content,
      sha256,
      enabled: true,
      source: 'bundle.chunk',
      updatedAt: generatedAt
    };

    rules.push(entry);
    activeChecksums.push(sha256);
    chunkRows = [];
  };

  while (true) {
    const response = await client.search({
      index: HASHES_INDEX_NAME,
      size: HASH_BUNDLE_SCAN_PAGE_SIZE,
      allow_no_indices: true,
      ignore_unavailable: true,
      body: {
        query: {
          bool: {
            must: [
              { term: { enabled: true } },
              { term: { 'validation.status': 'valid' } },
              {
                bool: {
                  should: [
                    { term: { severity: 'critical' } },
                    { term: { severity: 'crit' } }
                  ],
                  minimum_should_match: 1
                }
              }
            ]
          }
        },
        _source: ['sha256_hash', 'name', 'source', 'severity'],
        sort: [{ _id: { order: 'asc' } }],
        ...(searchAfter ? { search_after: searchAfter } : {})
      }
    });

    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    if (hits.length === 0) {
      break;
    }

    for (const hit of hits) {
      const source = hit?._source ?? {};
      if (!isEligibleHashBundleRule({
        enabled: source.enabled ?? true,
        severity: source.severity,
        source: source.source,
        validation: { status: source?.validation?.status ?? 'valid' }
      })) {
        continue;
      }

      const sha256 = normalizeHash(source.sha256_hash, 64);
      if (!sha256) {
        continue;
      }

      chunkRows.push({
        sha256_hash: sha256,
        name: String(source.name ?? `Malware SHA256 ${sha256.slice(0, 12)}`),
        severity: 'critical',
        source: String(source.source ?? 'unknown')
      });
      totalCriticalHashes += 1;

      if (chunkRows.length >= HASH_BUNDLE_CHUNK_SIZE) {
        flushChunk();
      }
    }

    const lastHit = hits[hits.length - 1];
    const lastSort = Array.isArray(lastHit?.sort) ? lastHit.sort : undefined;
    if (!lastSort || lastSort.length === 0 || hits.length < HASH_BUNDLE_SCAN_PAGE_SIZE) {
      break;
    }
    searchAfter = lastSort;
  }

  flushChunk();
  activeChecksums.sort((a, b) => a.localeCompare(b));

  return {
    dateVersion,
    bundleVersion,
    generatedAt,
    rules,
    activeChecksums,
    totalCriticalHashes
  };
}

async function ensureDailyHashBundleSnapshot(
  client: any,
  options?: { forceRebuild?: boolean }
): Promise<DailyHashBundleSnapshot> {
  const forceRebuild = Boolean(options?.forceRebuild);
  const today = todayDateVersion();
  if (!forceRebuild && dailyHashBundleSnapshot && dailyHashBundleSnapshot.dateVersion === today) {
    return dailyHashBundleSnapshot;
  }

  if (forceRebuild) {
    dailyHashBundleSnapshot = null;
  }

  if (!dailyHashBundleBuildInFlight) {
    dailyHashBundleBuildInFlight = (async () => {
      const snapshot = await buildDailyHashBundleSnapshot(client);
      dailyHashBundleSnapshot = snapshot;
      return snapshot;
    })().finally(() => {
      dailyHashBundleBuildInFlight = null;
    });
  }

  return dailyHashBundleBuildInFlight;
}

async function prebuildDailyHashBundleSnapshotBestEffort(
  client: any,
  options?: { forceRebuild?: boolean }
): Promise<void> {
  try {
    await ensureDailyHashBundleSnapshot(client, options);
  } catch (err: any) {
    // Keep sync completion resilient even if bundle prebuild fails.
    // eslint-disable-next-line no-console
    console.error('xdr-defense: failed to prebuild daily hash bundle snapshot', err);
  }
}

async function buildSignedHashBundle(client: any, policyId: string): Promise<{ bundle?: SignedBundleResponse; error?: string }> {
  const keyResult = getSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    return { error: keyResult.error ?? 'Signing key is unavailable.' };
  }

  const snapshot = await ensureDailyHashBundleSnapshot(client);
  const payload = {
    manifest_version: 1 as const,
    policy_id: policyId,
    bundle_version: snapshot.bundleVersion,
    generated_at: snapshot.generatedAt,
    signing_alg: 'ed25519' as const,
    rules: snapshot.rules,
    active_checksums: snapshot.activeChecksums
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

export function registerHashRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr-defense/hashes/rules',
      validate: {
        query: schema.object({
          q: schema.maybe(schema.string({ maxLength: 256 })),
          page: schema.maybe(schema.number({ min: 1, max: 100000 })),
          pageSize: schema.maybe(schema.number({ min: 1, max: 500 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch scoped client unavailable.' }
          });
        }

        const result = await listHashRulesIndexed(client, {
          q: req.query?.q,
          page: req.query?.page,
          pageSize: req.query?.pageSize
        });

        return res.ok({
          body: {
            rules: result.rules,
            page: result.page,
            pageSize: result.pageSize,
            total: result.total,
            totalPages: Math.max(1, Math.ceil(result.total / result.pageSize))
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to list hash rules from index.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/config',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => res.ok({ body: malwareBazaarStatusBody() })
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/config',
      validate: {
        body: schema.object({
          api_key: schema.string({ minLength: 1, maxLength: 512 })
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const saved = setMalwareBazaarApiKey(req.body?.api_key ?? '');
        updateMalwareBazaarSyncState({ api_key_updated_at: saved.updated_at, last_error: undefined });
        return res.ok({ body: malwareBazaarStatusBody() });
      } catch (err: any) {
        return res.customError({
          statusCode: 400,
          body: {
            message: 'Failed to save MalwareBazaar API key.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/rules',
      validate: {
        body: schema.object({
          name: schema.string({ minLength: 1, maxLength: 160 }),
          content: schema.string({ minLength: 1, maxLength: 200000 }),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch scoped client unavailable.' }
          });
        }

        const validation = validateHashContent(req.body?.content ?? '');
        if (validation.status === 'invalid') {
          return res.customError({
            statusCode: 400,
            body: {
              message: 'Hash rule validation failed.',
              validation
            }
          });
        }

        const lines = String(req.body?.content ?? '').split(/\r?\n/);
        let imported = 0;
        for (const line of lines) {
          const parsed = parseHashLine(line);
          if (!parsed) {
            continue;
          }

          const id = parsed.sha256
            ? parsed.sha256
            : parsed.md5
              ? `custom-md5-${parsed.md5}`
              : parsed.sha1
                ? `custom-sha1-${parsed.sha1}`
                : customDocId(line);

          const doc: HashIndexDocument = {
            first_seen_utc: undefined,
            sha256_hash: parsed.sha256,
            md5_hash: parsed.md5,
            sha1_hash: parsed.sha1,
            reporter: undefined,
            file_name: undefined,
            file_type_guess: undefined,
            mime_type: undefined,
            signature: undefined,
            clamav: undefined,
            vtpercent: undefined,
            imphash: undefined,
            ssdeep: undefined,
            tlsh: undefined,
            source: 'custom',
            updated_at: nowIso(),
            name: String(req.body?.name ?? 'custom-hash'),
            enabled: true,
            severity: String(req.body?.severity ?? 'medium'),
            tags: Array.isArray(req.body?.tags) ? req.body.tags.map((tag: unknown) => String(tag).trim()).filter((tag: string) => tag.length > 0) : [],
            content: String(req.body?.content ?? ''),
            validation
          };

          await upsertHashDocument(client, id, doc);
          imported += 1;
        }

        return res.ok({ body: { imported, validation } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to create hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/hashes/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }),
        body: schema.object({
          enabled: schema.maybe(schema.boolean()),
          content: schema.maybe(schema.string({ minLength: 1, maxLength: 200000 })),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 })),
          name: schema.maybe(schema.string({ minLength: 1, maxLength: 160 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const existing = await getHashDocument(client, req.params.id);
        if (!existing) {
          return res.customError({ statusCode: 404, body: { message: 'Rule not found.' } });
        }

        const nextContent = req.body?.content !== undefined ? String(req.body.content) : existing.content;
        const validation = validateHashContent(nextContent);
        const nextEnabled = validation.status === 'invalid' ? false : req.body?.enabled !== undefined ? Boolean(req.body.enabled) : Boolean(existing.enabled);
        const nextDoc: HashIndexDocument = {
          ...existing,
          name: req.body?.name !== undefined ? String(req.body.name) : existing.name,
          content: nextContent,
          severity: req.body?.severity !== undefined ? String(req.body.severity) : existing.severity,
          tags: req.body?.tags !== undefined
            ? req.body.tags.map((tag: unknown) => String(tag).trim()).filter((tag: string) => tag.length > 0)
            : existing.tags,
          enabled: nextEnabled,
          updated_at: nowIso(),
          validation
        };

        await upsertHashDocument(client, req.params.id, nextDoc);
        return res.ok({ body: { id: req.params.id, ...nextDoc, updatedAt: nextDoc.updated_at } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to update hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.delete(
    {
      path: '/api/xdr-defense/hashes/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const deleted = await deleteHashDocument(client, req.params.id);
        if (!deleted) {
          return res.customError({ statusCode: 404, body: { message: 'Rule not found.' } });
        }

        return res.ok({ body: { deleted: true, id: req.params.id } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to delete hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/bundle',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const policyId = String(req.query?.policy_id ?? 'global-default');
        const keyResult = getSigningPrivateKey();
        if (!keyResult.ok) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed hash bundle generation unavailable.',
              details: keyResult.error
            }
          });
        }

        await prebuildDailyHashBundleSnapshotBestEffort(client, { forceRebuild: true });
        const result = await buildSignedHashBundle(client, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed hash bundle generation unavailable.',
              details: result.error ?? 'Failed to sign bundle.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build hash bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/bundle/build',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const policyId = String(req.body?.policy_id ?? 'global-default');
        const keyResult = getSigningPrivateKey();
        if (!keyResult.ok) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Hash bundle signing unavailable.',
              details: keyResult.error
            }
          });
        }

        const result = await buildSignedHashBundle(client, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Hash bundle generation failed.',
              details: result.error ?? 'Unknown error.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build hash bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  const syncApiHandler = async (ctx: any, _req: any, res: any) => {
    if (malwareBazaarSyncInFlight) {
      return syncAlreadyRunningResponse(res, 'malwarebazaar_api');
    }

    const client = scopedOsClient(ctx);
    if (!client) {
      return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
    }

    malwareBazaarSyncInFlight = true;
    try {
      const result = await performMalwareBazaarSync(client);
      return res.ok({ body: { ...result, started: true } });
    } catch (err: any) {
      const completedAt = nowIso();
      malwareBazaarSyncMetadata = {
        ...malwareBazaarSyncMetadata,
        status: 'failed',
        phase: 'failed',
        completed_at: completedAt,
        message: 'MalwareBazaar hash sync failed.',
        errors: [String(err?.message ?? err)]
      };
      updateMalwareBazaarSyncState({
        status: 'failed',
        phase: 'failed',
        message: malwareBazaarSyncMetadata.message,
        last_attempted_at: malwareBazaarSyncMetadata.started_at ?? completedAt,
        last_completed_at: completedAt,
        last_error: String(err?.message ?? err)
      });
      return res.customError({
        statusCode: String(err?.message ?? err).includes('Configure a MalwareBazaar API key') ? 400 : 502,
        body: {
          message: 'Failed to sync MalwareBazaar hashes.',
          details: String(err?.message ?? err),
          status: malwareBazaarStatusBody()
        }
      });
    } finally {
      malwareBazaarSyncInFlight = false;
      if (malwareBazaarSyncMetadata.status !== 'processing') {
        malwareBazaarSyncMetadata = { status: 'idle' };
      }
    }
  };

  const syncFullCsvHandler = async (ctx: any, _req: any, res: any) => {
    if (malwareBazaarSyncInFlight) {
      return syncAlreadyRunningResponse(res, 'daily_full_csv');
    }

    const client = scopedOsClient(ctx);
    if (!client) {
      return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
    }

    malwareBazaarSyncInFlight = true;

    void (async () => {
      try {
        await performMalwareBazaarDailyFullSync(client);
      } catch (err: any) {
        const completedAt = nowIso();
        malwareBazaarSyncMetadata = {
          ...malwareBazaarSyncMetadata,
          status: 'failed',
          phase: 'failed',
          completed_at: completedAt,
          message: 'MalwareBazaar daily full CSV sync failed.',
          errors: [String(err?.message ?? err)]
        };
        updateMalwareBazaarSyncState({
          status: 'failed',
          phase: 'failed',
          message: malwareBazaarSyncMetadata.message,
          last_attempted_at: malwareBazaarSyncMetadata.started_at ?? completedAt,
          last_completed_at: completedAt,
          last_error: String(err?.message ?? err)
        });
      } finally {
        malwareBazaarSyncInFlight = false;
        if (malwareBazaarSyncMetadata.status !== 'processing') {
          malwareBazaarSyncMetadata = { status: 'idle' };
        }
      }
    })();

    return res.ok({
      body: {
        message: 'MalwareBazaar daily sync started.',
        mode: 'daily_full_csv',
        started: true,
        status: malwareBazaarStatusBody()
      }
    });
  };

  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/sync',
      validate: false
    },
    syncApiHandler
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/full/sync',
      validate: false
    },
    syncFullCsvHandler
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/open-source/sync',
      validate: false
    },
    syncApiHandler
  );
}
