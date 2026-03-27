declare const require: any;
const console = (globalThis as any).console;

import { getMbAutoUpdateSettings } from './upstream_sync_store';
import { getMalwareBazaarApiKey } from './secret_store';
import { lookupHashInfo } from './malwarebazaar';
import { HASHES_INDEX_NAME, ensureHashesIndex } from './hashes_index';

const UPDATE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const WINDOW_MINUTES = 5;

export function callsPerWindow(requestsPerDay: number): number {
  return Math.floor(requestsPerDay * WINDOW_MINUTES / (24 * 60));
}

async function fetchEnrichmentCandidates(client: any, limit: number): Promise<Array<{ id: string; sha256: string }>> {
  await ensureHashesIndex(client);
  const response = await client.search({
    index: HASHES_INDEX_NAME,
    body: {
      query: { match_all: {} },
      sort: [{ updated_at: { order: 'asc' } }],
      size: limit,
      _source: ['sha256_hash']
    }
  });

  const hits: any[] = response?.body?.hits?.hits ?? response?.hits?.hits ?? [];
  return hits
    .map((hit: any) => ({
      id: String(hit._id ?? ''),
      sha256: String(hit._source?.sha256_hash ?? '')
    }))
    .filter((item) => /^[a-f0-9]{64}$/.test(item.sha256));
}

async function enrichDocument(client: any, candidate: { id: string; sha256: string }, apiKey: string): Promise<boolean> {
  let info;
  try {
    info = await lookupHashInfo({ apiKey, sha256: candidate.sha256 });
  } catch (err: any) {
    console.warn(`[xdr-defense] mb_auto_update: lookup failed for ${candidate.sha256}: ${String(err?.message ?? err)}`);
    return false;
  }

  if (!info) {
    // Hash not found in MalwareBazaar — bump updated_at to avoid re-querying constantly
    await client.update({
      index: HASHES_INDEX_NAME,
      id: candidate.id,
      body: {
        doc: { updated_at: new Date().toISOString() }
      },
      retry_on_conflict: 2
    }).catch(() => undefined);
    return true;
  }

  const patch: Record<string, unknown> = {
    updated_at: new Date().toISOString()
  };

  if (info.vtpercent !== undefined) patch.vtpercent = info.vtpercent;
  if (info.clamav !== undefined) patch.clamav = info.clamav;
  if (info.signature !== undefined) patch.signature = info.signature;
  if (info.sha3_384_hash !== undefined) patch.sha3_384_hash = info.sha3_384_hash;
  if (info.md5_hash !== undefined) patch.md5_hash = info.md5_hash;
  if (info.sha1_hash !== undefined) patch.sha1_hash = info.sha1_hash;
  if (info.reporter !== undefined) patch.reporter = info.reporter;
  if (info.file_name !== undefined) patch.file_name = info.file_name;
  if (info.file_type_guess !== undefined) patch.file_type_guess = info.file_type_guess;
  if (info.file_format !== undefined) patch.file_format = info.file_format;
  if (info.file_arch !== undefined) patch.file_arch = info.file_arch;
  if (info.mime_type !== undefined) patch.mime_type = info.mime_type;
  if (info.imphash !== undefined) patch.imphash = info.imphash;
  if (info.telfhash !== undefined) patch.telfhash = info.telfhash;
  if (info.gimphash !== undefined) patch.gimphash = info.gimphash;
  if (info.magika !== undefined) patch.magika = info.magika;
  if (info.dhash_icon !== undefined) patch.dhash_icon = info.dhash_icon;
  if (info.trid !== undefined) patch.trid = info.trid;
  if (info.comment !== undefined) patch.comment = info.comment;
  if (info.archive_pw !== undefined) patch.archive_pw = info.archive_pw;
  if (info.delivery_method !== undefined) patch.delivery_method = info.delivery_method;
  if (info.code_sign !== undefined) patch.code_sign = info.code_sign;
  if (info.origin_country !== undefined) patch.origin_country = info.origin_country;
  if (info.anonymous !== undefined) patch.anonymous = info.anonymous;
  if (info.intelligence_uploads !== undefined) patch.intelligence_uploads = info.intelligence_uploads;
  if (info.intelligence_downloads !== undefined) patch.intelligence_downloads = info.intelligence_downloads;
  if (info.intelligence_mail !== undefined) patch.intelligence_mail = info.intelligence_mail;
  if (info.intelligence_clamav !== undefined) patch.intelligence_clamav = info.intelligence_clamav;
  if (info.ssdeep !== undefined) patch.ssdeep = info.ssdeep;
  if (info.tlsh !== undefined) patch.tlsh = info.tlsh;
  if (info.first_seen !== undefined) patch.first_seen_utc = info.first_seen;
  if (info.last_seen_utc !== undefined) patch.last_seen_utc = info.last_seen_utc;
  if (info.file_size !== undefined) patch.file_size = info.file_size;
  if (Array.isArray(info.tags) && info.tags.length > 0) patch.tags = info.tags;

  await client.update({
    index: HASHES_INDEX_NAME,
    id: candidate.id,
    body: { doc: patch },
    retry_on_conflict: 2
  }).catch((err: any) => {
    console.warn(`[xdr-defense] mb_auto_update: failed to update ${candidate.id}: ${String(err?.message ?? err)}`);
    return undefined;
  });

  return true;
}

class MbAutoUpdateScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;
  private client: any = null;
  private running = false;

  init(client: any): void {
    this.client = client;
    const settings = getMbAutoUpdateSettings();
    if (settings.enabled) {
      this.startTimer();
    }
  }

  applySettings(settings: { enabled: boolean; requests_per_day: number }): void {
    if (settings.enabled) {
      this.restartTimer();
    } else {
      this.stopTimer();
    }
  }

  private startTimer(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.runCycle().catch((err: any) => {
        console.warn(`[xdr-defense] mb_auto_update cycle error: ${String(err?.message ?? err)}`);
      });
    }, UPDATE_INTERVAL_MS);
  }

  private stopTimer(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private restartTimer(): void {
    this.stopTimer();
    this.startTimer();
  }

  async runSingleRequestNow(clientOverride?: any): Promise<{ attempted: number; enriched: number }> {
    if (this.running) {
      throw new Error('Auto-update cycle is already running. Please retry in a few seconds.');
    }

    const client = clientOverride ?? this.client;
    if (!client) {
      throw new Error('OpenSearch client unavailable for auto-update sync.');
    }

    this.running = true;
    try {
      const apiKey = getMalwareBazaarApiKey();
      if (!apiKey) {
        throw new Error('MalwareBazaar API key is not configured.');
      }

      // Manual test action: always perform exactly one lookup request when possible.
      const candidates = await fetchEnrichmentCandidates(client, 1);
      if (candidates.length === 0) {
        return { attempted: 0, enriched: 0 };
      }

      const ok = await enrichDocument(client, candidates[0], apiKey);
      return { attempted: 1, enriched: ok ? 1 : 0 };
    } finally {
      this.running = false;
    }
  }

  async runCycle(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const settings = getMbAutoUpdateSettings();
      if (!settings.enabled) return;

      const limit = callsPerWindow(settings.requests_per_day);
      if (limit < 1) return;

      const apiKey = getMalwareBazaarApiKey();
      if (!apiKey) return;

      const candidates = await fetchEnrichmentCandidates(this.client, limit);
      let enriched = 0;
      for (const candidate of candidates) {
        if (await enrichDocument(this.client, candidate, apiKey)) {
          enriched += 1;
        }
      }

      if (enriched > 0) {
        console.log(`[xdr-defense] mb_auto_update: enriched ${enriched} hash(es)`);
      }
    } finally {
      this.running = false;
    }
  }

  destroy(): void {
    this.stopTimer();
  }
}

export const mbAutoUpdateScheduler = new MbAutoUpdateScheduler();
