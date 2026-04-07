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
import {
  bumpImmediateCustomHashOverlayBundleVersion,
  clearImmediateCustomHashOverlayState,
  getImmediateCustomHashOverlayState,
  isEligibleImmediateCustomHashOverlayDocument,
  reconcileImmediateCustomHashOverlayState
} from '../lib/hash_custom_overlay_state';
import {
  ensureHashRolloutStatusIndex,
  ingestHashRolloutStatusReport,
  listHashRolloutStatus
} from '../lib/hash_rollout_status';
import { getMalwareBazaarApiKey, getMalwareBazaarApiKeyStatus, setMalwareBazaarApiKey } from '../lib/secret_store';
import { getSigningPrivateKey } from '../lib/signing_keys';
import { getMalwareBazaarSyncState, updateMalwareBazaarSyncState, getMbAutoUpdateSettings, saveMbAutoUpdateSettings } from '../lib/upstream_sync_store';
import { validateHashContent } from '../lib/hashes_store';
import { mbAutoUpdateScheduler, callsPerWindow } from '../lib/mb_auto_update';

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
const HASH_BUNDLE_CHUNK_SIZE = 1000;
const HASH_BUNDLE_SCAN_PAGE_SIZE = 10000;

interface DailyHashBundleSnapshot {
  dateVersion: string;
  bundleVersion: number;
  generatedAt: string;
  rules: BundleRuleEntry[];
  activeChecksums: string[];
  totalCriticalHashes: number;
  includedCriticalSha256Hashes: string[];
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

type FieldErrorMap = Record<string, string[]>;

function addFieldError(fieldErrors: FieldErrorMap, field: string, message: string): void {
  if (!fieldErrors[field]) {
    fieldErrors[field] = [];
  }
  fieldErrors[field].push(message);
}

function hasFieldErrors(fieldErrors: FieldErrorMap): boolean {
  return Object.keys(fieldErrors).length > 0;
}

function validateHexHashField(
  raw: unknown,
  length: number,
  field: string,
  label: string,
  fieldErrors: FieldErrorMap
): string | undefined {
  const value = String(raw ?? '').trim();
  if (!value) {
    return undefined;
  }
  const re = new RegExp(`^[a-fA-F0-9]{${length}}$`);
  if (!re.test(value)) {
    addFieldError(fieldErrors, field, `${label} must be exactly ${length} hexadecimal characters.`);
    return undefined;
  }
  return value.toLowerCase();
}

function normalizeStoredSeverity(raw: unknown): string {
  const value = String(raw ?? 'medium').trim().toLowerCase();
  return value || 'medium';
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
    if (vtpercent >= 75) {
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
    sha3_384_hash: normalizeHash(input.sample.sha3_384_hash, 96),
    md5_hash: normalizeHash(input.sample.md5_hash, 32),
    sha1_hash: normalizeHash(input.sample.sha1_hash, 40),
    reporter: cleanString(input.sample.reporter),
    file_name: cleanString(input.sample.file_name),
    file_type_guess: cleanString(input.sample.file_type_guess),
    file_format: cleanString(input.sample.file_format),
    file_arch: cleanString(input.sample.file_arch),
    mime_type: cleanString(input.sample.mime_type),
    signature,
    clamav: cleanString(input.sample.clamav),
    vtpercent: cleanString(input.sample.vtpercent),
    imphash: normalizeHash(input.sample.imphash, 32),
    telfhash: cleanString(input.sample.telfhash),
    gimphash: cleanString(input.sample.gimphash),
    magika: cleanString(input.sample.magika),
    dhash_icon: cleanString(input.sample.dhash_icon),
    trid: cleanString(input.sample.trid),
    comment: cleanString(input.sample.comment),
    archive_pw: cleanString(input.sample.archive_pw),
    delivery_method: cleanString(input.sample.delivery_method),
    code_sign: cleanString(input.sample.code_sign),
    origin_country: cleanString(input.sample.origin_country),
    anonymous: typeof input.sample.anonymous === 'boolean' ? input.sample.anonymous : undefined,
    intelligence_uploads:
      typeof input.sample.intelligence_uploads === 'number' && Number.isFinite(input.sample.intelligence_uploads)
        ? input.sample.intelligence_uploads
        : undefined,
    intelligence_downloads:
      typeof input.sample.intelligence_downloads === 'number' && Number.isFinite(input.sample.intelligence_downloads)
        ? input.sample.intelligence_downloads
        : undefined,
    intelligence_mail: cleanString(input.sample.intelligence_mail),
    intelligence_clamav: cleanString(input.sample.intelligence_clamav),
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
    sha3_384_hash: doc.sha3_384_hash,
    md5_hash: doc.md5_hash,
    sha1_hash: doc.sha1_hash,
    reporter: doc.reporter,
    file_name: doc.file_name,
    file_type_guess: doc.file_type_guess,
    file_format: doc.file_format,
    file_arch: doc.file_arch,
    mime_type: doc.mime_type,
    signature: doc.signature,
    clamav: doc.clamav,
    vtpercent: doc.vtpercent,
    imphash: doc.imphash,
    telfhash: doc.telfhash,
    gimphash: doc.gimphash,
    magika: doc.magika,
    dhash_icon: doc.dhash_icon,
    trid: doc.trid,
    comment: doc.comment,
    archive_pw: doc.archive_pw,
    delivery_method: doc.delivery_method,
    code_sign: doc.code_sign,
    origin_country: doc.origin_country,
    anonymous: doc.anonymous,
    intelligence_uploads: doc.intelligence_uploads,
    intelligence_downloads: doc.intelligence_downloads,
    intelligence_mail: doc.intelligence_mail,
    intelligence_clamav: doc.intelligence_clamav,
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
  clearImmediateCustomHashOverlayState();

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
  clearImmediateCustomHashOverlayState();

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

function buildCustomHashContent(input: { sha256_hash?: string; md5_hash?: string; sha1_hash?: string }): string {
  const lines: string[] = [];
  if (input.sha256_hash) {
    lines.push(`sha256:${input.sha256_hash}`);
  }
  if (input.md5_hash) {
    lines.push(`md5:${input.md5_hash}`);
  }
  if (input.sha1_hash) {
    lines.push(`sha1:${input.sha1_hash}`);
  }
  return lines.join('\n');
}

interface HashYamlChunkItem {
  sha256_hash: string;
  name: string;
  severity?: string;
  family?: string;
  mime_type?: string;
  first_seen_utc?: string;
}

function yamlScalar(value: string): string {
  const escaped = value.replace(/'/g, "''");
  return /[:#\[\]{},|>&*!?'"\\]/.test(value) ? `'${escaped}'` : value;
}

function hashYamlChunkContent(items: HashYamlChunkItem[]): string {
  if (items.length === 0) {
    return 'hashes: []\n';
  }

  const lines: string[] = ['hashes:'];
  for (const item of items) {
    lines.push(`  - sha256: ${item.sha256_hash}`);
    lines.push(`    name: ${yamlScalar(item.name)}`);
    if (item.severity) {
      lines.push(`    severity: ${yamlScalar(item.severity)}`);
    }
    if (item.family) {
      lines.push(`    family: ${yamlScalar(item.family)}`);
    }
    if (item.mime_type) {
      lines.push(`    mime_type: ${yamlScalar(item.mime_type)}`);
    }
    if (item.first_seen_utc) {
      lines.push(`    first_seen_utc: ${yamlScalar(item.first_seen_utc)}`);
    }
  }

  return `${lines.join('\n')}\n`;
}

function signHashBundlePayload(payload: Omit<SignedBundleResponse, 'signature_base64' | 'signed_payload_base64'>): {
  bundle?: SignedBundleResponse;
  error?: string;
} {
  const keyResult = getSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    return { error: keyResult.error ?? 'Signing key is unavailable.' };
  }

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

async function buildDailyHashBundleSnapshot(client: any): Promise<DailyHashBundleSnapshot> {
  await ensureHashesIndex(client);

  const dateVersion = todayDateVersion();
  const generatedAt = `${dateVersion}T00:00:00.000Z`;
  const bundleVersion = dateVersionToBundleVersion(dateVersion);
  const rules: BundleRuleEntry[] = [];
  const activeChecksums: string[] = [];

  let searchAfter: unknown[] | undefined;
  let chunkRows: HashYamlChunkItem[] = [];
  let chunkSeq = 0;
  let totalCriticalHashes = 0;
  const includedCriticalSha256Hashes = new Set<string>();

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
        _source: ['sha256_hash', 'name', 'severity', 'source', 'signature', 'mime_type', 'first_seen_utc'],
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
      const sha256 = normalizeHash(source.sha256_hash, 64);
      if (!sha256) {
        continue;
      }

      chunkRows.push({
        sha256_hash: sha256,
        name: String(source.name ?? `Malware SHA256 ${sha256.slice(0, 12)}`),
        severity: cleanString(source.severity),
        family: cleanString(source.signature),
        mime_type: cleanString(source.mime_type),
        first_seen_utc: cleanString(source.first_seen_utc)
      });
      includedCriticalSha256Hashes.add(sha256);
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
    totalCriticalHashes,
    includedCriticalSha256Hashes: [...includedCriticalSha256Hashes].sort((left, right) => left.localeCompare(right))
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
  const snapshot = await ensureDailyHashBundleSnapshot(client);
  return signHashBundlePayload({
    manifest_version: 1 as const,
    policy_id: policyId,
    bundle_version: snapshot.bundleVersion,
    generated_at: snapshot.generatedAt,
    signing_alg: 'ed25519' as const,
    rules: snapshot.rules,
    active_checksums: snapshot.activeChecksums
  });
}

async function buildSignedImmediateCustomHashOverlayBundle(
  client: any,
  policyId: string
): Promise<{ bundle?: SignedBundleResponse; error?: string }> {
  let overlayState = getImmediateCustomHashOverlayState();
  const fullSnapshotSha256 = new Set<string>(dailyHashBundleSnapshot?.includedCriticalSha256Hashes ?? []);
  const docs = await Promise.all(
    overlayState.pending_doc_ids.map(async (id) => ({
      id,
      doc: await getHashDocument(client, id)
    }))
  );

  const staleMutations: Array<{ id: string; doc: null }> = [];
  const customRowsBySha256 = new Map<string, HashYamlChunkItem>();

  for (const entry of docs) {
    if (!isEligibleImmediateCustomHashOverlayDocument(entry.doc)) {
      staleMutations.push({ id: entry.id, doc: null });
      continue;
    }

    const sha256 = normalizeHash(entry.doc?.sha256_hash, 64);
    if (!sha256 || !entry.doc) {
      staleMutations.push({ id: entry.id, doc: null });
      continue;
    }

    if (fullSnapshotSha256.has(sha256)) {
      continue;
    }

    if (!customRowsBySha256.has(sha256)) {
      customRowsBySha256.set(sha256, {
        sha256_hash: sha256,
        name: String(entry.doc.name ?? `Custom SHA256 ${sha256.slice(0, 12)}`),
        severity: cleanString(entry.doc.severity),
        family: cleanString(entry.doc.signature),
        mime_type: cleanString(entry.doc.mime_type),
        first_seen_utc: cleanString(entry.doc.first_seen_utc)
      });
    }
  }

  if (staleMutations.length > 0) {
    overlayState = reconcileImmediateCustomHashOverlayState(staleMutations);
  }

  const rules: BundleRuleEntry[] = [];
  const customRows = [...customRowsBySha256.values()].sort((left, right) => left.sha256_hash.localeCompare(right.sha256_hash));
  if (customRows.length > 0) {
    const dateVersion = todayDateVersion();
    const fileBase = `custom-critical-hashes-${dateVersion}-00001`;
    const content = hashYamlChunkContent(customRows);
    rules.push({
      id: fileBase,
      filename: `${fileBase}.yaml`,
      content,
      sha256: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
      enabled: true,
      source: 'custom.overlay',
      updatedAt: overlayState.generated_at
    });
  }

  rules.sort((left, right) => left.id.localeCompare(right.id));
  const activeChecksums = rules.map((rule) => rule.sha256).sort((left, right) => left.localeCompare(right));

  return signHashBundlePayload({
    manifest_version: 1 as const,
    policy_id: policyId,
    bundle_version: overlayState.bundle_version,
    generated_at: overlayState.generated_at,
    signing_alg: 'ed25519' as const,
    rules,
    active_checksums: activeChecksums
  });
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
          name: schema.maybe(schema.string({ maxLength: 160 })),
          content: schema.maybe(schema.string({ maxLength: 200000 })),
          enabled: schema.maybe(schema.boolean()),
          severity: schema.maybe(schema.string({ maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 })),
          sha256_hash: schema.maybe(schema.string({ maxLength: 64 })),
          md5_hash: schema.maybe(schema.string({ maxLength: 32 })),
          sha1_hash: schema.maybe(schema.string({ maxLength: 40 })),
          reporter: schema.maybe(schema.string({ maxLength: 256 })),
          file_name: schema.maybe(schema.string({ maxLength: 512 })),
          file_type_guess: schema.maybe(schema.string({ maxLength: 128 })),
          mime_type: schema.maybe(schema.string({ maxLength: 256 })),
          signature: schema.maybe(schema.string({ maxLength: 256 })),
          clamav: schema.maybe(schema.string({ maxLength: 512 })),
          vtpercent: schema.maybe(schema.string({ maxLength: 32 })),
          imphash: schema.maybe(schema.string({ maxLength: 32 })),
          ssdeep: schema.maybe(schema.string({ maxLength: 512 })),
          tlsh: schema.maybe(schema.string({ maxLength: 128 }))
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

        const fieldErrors: FieldErrorMap = {};
        const sha256Hash = validateHexHashField(req.body?.sha256_hash, 64, 'sha256_hash', 'SHA256', fieldErrors);
        const md5Hash = validateHexHashField(req.body?.md5_hash, 32, 'md5_hash', 'MD5', fieldErrors);
        const sha1Hash = validateHexHashField(req.body?.sha1_hash, 40, 'sha1_hash', 'SHA1', fieldErrors);
        const normalizedImphash = validateHexHashField(req.body?.imphash, 32, 'imphash', 'imphash', fieldErrors);
        const explicitHashContent = buildCustomHashContent({
          sha256_hash: sha256Hash,
          md5_hash: md5Hash,
          sha1_hash: sha1Hash
        });

        const rawContent = String(req.body?.content ?? '').trim();
        const content = explicitHashContent || rawContent;
        if (!content) {
          const message = 'Provide at least one hash value (SHA256, MD5, or SHA1).';
          addFieldError(fieldErrors, 'sha256_hash', message);
          addFieldError(fieldErrors, 'md5_hash', message);
          addFieldError(fieldErrors, 'sha1_hash', message);
        }

        if (hasFieldErrors(fieldErrors)) {
          return res.customError({
            statusCode: 400,
            body: {
              message: 'Hash rule request validation failed.',
              field_errors: fieldErrors
            }
          });
        }

        const validation = validateHashContent(content);
        if (validation.status === 'invalid') {
          return res.customError({
            statusCode: 400,
            body: {
              message: 'Hash rule validation failed.',
              validation
            }
          });
        }

        const trimmedTags = Array.isArray(req.body?.tags)
          ? req.body.tags.map((tag: unknown) => String(tag).trim()).filter((tag: string) => tag.length > 0)
          : [];

        if (explicitHashContent) {
          const id = sha256Hash
            ? sha256Hash
            : md5Hash
              ? `custom-md5-${md5Hash}`
              : sha1Hash
                ? `custom-sha1-${sha1Hash}`
                : customDocId(content);

          const fallbackName = cleanString(req.body?.signature)
            ?? cleanString(req.body?.file_name)
            ?? (sha256Hash ? `Custom SHA256 ${sha256Hash.slice(0, 12)}` : 'custom-hash');

          const doc: HashIndexDocument = {
            first_seen_utc: undefined,
            sha256_hash: sha256Hash,
            md5_hash: md5Hash,
            sha1_hash: sha1Hash,
            reporter: cleanString(req.body?.reporter),
            file_name: cleanString(req.body?.file_name),
            file_type_guess: cleanString(req.body?.file_type_guess),
            mime_type: cleanString(req.body?.mime_type),
            signature: cleanString(req.body?.signature),
            clamav: cleanString(req.body?.clamav),
            vtpercent: cleanString(req.body?.vtpercent),
            imphash: normalizedImphash,
            ssdeep: cleanString(req.body?.ssdeep),
            tlsh: cleanString(req.body?.tlsh),
            source: 'custom',
            updated_at: nowIso(),
            name: cleanString(req.body?.name) ?? fallbackName,
            enabled: req.body?.enabled !== undefined ? Boolean(req.body.enabled) : true,
            severity: normalizeStoredSeverity(req.body?.severity),
            tags: trimmedTags,
            content,
            validation
          };

          const result = await upsertHashDocument(client, id, doc);
          reconcileImmediateCustomHashOverlayState([{ id, doc, forceVersionBump: true }]);
          return res.ok({ body: { imported: 1, result, id, validation } });
        }

        const overlayMutations: Array<{ id: string; doc: HashIndexDocument; forceVersionBump: true }> = [];
        const lines = rawContent.split(/\r?\n/);
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
            reporter: cleanString(req.body?.reporter),
            file_name: cleanString(req.body?.file_name),
            file_type_guess: cleanString(req.body?.file_type_guess),
            mime_type: cleanString(req.body?.mime_type),
            signature: cleanString(req.body?.signature),
            clamav: cleanString(req.body?.clamav),
            vtpercent: cleanString(req.body?.vtpercent),
            imphash: normalizedImphash,
            ssdeep: cleanString(req.body?.ssdeep),
            tlsh: cleanString(req.body?.tlsh),
            source: 'custom',
            updated_at: nowIso(),
            name: cleanString(req.body?.name) ?? 'custom-hash',
            enabled: req.body?.enabled !== undefined ? Boolean(req.body.enabled) : true,
            severity: normalizeStoredSeverity(req.body?.severity),
            tags: trimmedTags,
            content: line.trim(),
            validation
          };

          await upsertHashDocument(client, id, doc);
          overlayMutations.push({ id, doc, forceVersionBump: true });
          imported += 1;
        }

        if (imported > 0) {
          reconcileImmediateCustomHashOverlayState(overlayMutations);
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
          severity: req.body?.severity !== undefined ? normalizeStoredSeverity(req.body.severity) : existing.severity,
          tags: req.body?.tags !== undefined
            ? req.body.tags.map((tag: unknown) => String(tag).trim()).filter((tag: string) => tag.length > 0)
            : existing.tags,
          enabled: nextEnabled,
          updated_at: nowIso(),
          validation
        };

        await upsertHashDocument(client, req.params.id, nextDoc);
        if (existing.source === 'custom') {
          reconcileImmediateCustomHashOverlayState([{ id: req.params.id, doc: nextDoc, forceVersionBump: true }]);
        } else {
          await prebuildDailyHashBundleSnapshotBestEffort(client, { forceRebuild: true });
        }
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

        const existing = await getHashDocument(client, req.params.id);
        const deleted = await deleteHashDocument(client, req.params.id);
        if (!deleted) {
          return res.customError({ statusCode: 404, body: { message: 'Rule not found.' } });
        }

        if (existing?.source === 'custom') {
          reconcileImmediateCustomHashOverlayState([{ id: req.params.id, doc: null }]);
        } else {
          await prebuildDailyHashBundleSnapshotBestEffort(client, { forceRebuild: true });
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
      path: '/api/xdr-defense/hashes/custom-overlay/bundle',
      options: {
        authRequired: false
      },
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
              message: 'Signed custom hash overlay bundle generation unavailable.',
              details: keyResult.error
            }
          });
        }

        const result = await buildSignedImmediateCustomHashOverlayBundle(client, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed custom hash overlay bundle generation unavailable.',
              details: result.error ?? 'Failed to sign bundle.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build custom hash overlay bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/bundle',
      options: {
        authRequired: false
      },
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

        // Use the cached daily snapshot built after each sync. The forceRebuild
        // happens inside performMalwareBazaarSync / performMalwareBazaarDailyFullSync
        // so agents always receive the most recently built bundle without triggering
        // a full index scan on every poll.
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

  router.post(
    {
      path: '/api/xdr-defense/hashes/rollouts/status/report',
      options: {
        authRequired: false
      },
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1, maxLength: 256 }),
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
          state: schema.string({ minLength: 1, maxLength: 64 }),
          full_bundle_version: schema.maybe(schema.number({ min: 0 })),
          custom_bundle_version: schema.maybe(schema.number({ min: 0 })),
          reported_at: schema.maybe(schema.oneOf([schema.number({ min: 0 }), schema.string({ minLength: 1, maxLength: 128 })])),
          error: schema.maybe(schema.string({ minLength: 1, maxLength: 4096 })),
          agent_hostname: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        await ensureHashRolloutStatusIndex(client);
        const result = await ingestHashRolloutStatusReport(client, req.body ?? {});
        return res.ok({ body: result });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to ingest hash rollout status report.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/rollouts/status',
      validate: {
        query: schema.object({
          page: schema.maybe(schema.number({ min: 1, max: 100000 })),
          pageSize: schema.maybe(schema.number({ min: 1, max: 500 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        await ensureHashRolloutStatusIndex(client);
        const result = await listHashRolloutStatus(client, {
          page: req.query?.page,
          pageSize: req.query?.pageSize
        });
        return res.ok({ body: result });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to list hash rollout status.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/rollouts/retry',
      validate: false
    },
    async (_ctx: any, _req: any, res: any) => {
      try {
        const state = bumpImmediateCustomHashOverlayBundleVersion();
        return res.ok({
          body: {
            success: true,
            message: 'Hash rollout retry accepted. Custom overlay bundle version bumped.',
            overlay_bundle_version: state.bundle_version,
            pending_custom_entries: state.pending_doc_ids.length,
            generated_at: state.generated_at
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to retry hash rollout.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/rollout',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const policyId = String(req.body?.policy_id ?? 'global-default');
        const snapshot = dailyHashBundleSnapshot;

        if (!snapshot) {
          return res.customError({
            statusCode: 409,
            body: {
              started: false,
              success: false,
              message: "No cached hash bundle available. Run 'Sync MalwareBazaar Daily' first.",
              policy_id: policyId
            }
          });
        }

        return res.ok({
          body: {
            started: true,
            success: true,
            message: 'Cached hash rollout snapshot is ready. Agents will receive the cached hash bundle on next policy poll.',
            policy_id: policyId,
            dateVersion: snapshot.dateVersion,
            bundle_version: snapshot.bundleVersion,
            generated_at: snapshot.generatedAt,
            rule_count: snapshot.rules.length,
            total_critical_hashes: snapshot.totalCriticalHashes,
            active_checksum_count: snapshot.activeChecksums.length
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to roll out hashes to agents.',
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

  // GET auto-update settings
  router.get(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/auto-update-settings',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      const settings = getMbAutoUpdateSettings();
      return res.ok({
        body: {
          enabled: settings.enabled,
          requests_per_day: settings.requests_per_day,
          calls_per_window: callsPerWindow(settings.requests_per_day)
        }
      });
    }
  );

  // POST auto-update settings
  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/auto-update-settings',
      validate: {
        body: schema.object({
          enabled: schema.boolean(),
          requests_per_day: schema.number({ min: 1, max: 100000 })
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const saved = saveMbAutoUpdateSettings({
          enabled: Boolean(req.body?.enabled),
          requests_per_day: Math.round(Number(req.body?.requests_per_day) || 1000)
        });
        mbAutoUpdateScheduler.applySettings(saved);
        return res.ok({
          body: {
            enabled: saved.enabled,
            requests_per_day: saved.requests_per_day,
            calls_per_window: callsPerWindow(saved.requests_per_day)
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 400,
          body: {
            message: 'Failed to save auto-update settings.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  // POST one-shot auto-update test (always one upstream request when a candidate exists)
  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/auto-update-sync-now',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const result = await mbAutoUpdateScheduler.runSingleRequestNow(client);
        return res.ok({
          body: {
            attempted: result.attempted,
            enriched: result.enriched,
            message:
              result.attempted === 0
                ? 'No eligible hash documents were found for auto-update.'
                : 'Manual auto-update sync completed.'
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 400,
          body: {
            message: 'Failed to run MalwareBazaar auto-update sync now.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );
}
