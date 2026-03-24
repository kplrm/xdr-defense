declare const require: any;

const https = require('https');
const os = require('os');

export interface HashSourceFeed {
  id: string;
  name: string;
  severity?: string;
  tags?: string[];
  content?: string;
  url?: string;
}

export interface HashSyncResult {
  worker_count: number;
  attempted: number;
  succeeded: number;
  failed: number;
  items: Array<{
    id: string;
    name: string;
    ok: boolean;
    content?: string;
    error?: string;
  }>;
}

const BUILTIN_HASH_FEED: HashSourceFeed[] = [
  {
    id: 'malwarebazaar-emotet-sample',
    name: 'MalwareBazaar Emotet Sample Set',
    severity: 'high',
    tags: ['malwarebazaar', 'emotet', 'synced'],
    content:
      'sha256:bd2e35f9f5f9be7d6e3f5914e4fba6f1dc0dbd3f9cb7a7d3be2df3d49002f7df\n' +
      'sha256:6f2af3f7d9da2e9b9841c843f4f89d8f22d3a3f75cc9e70b2dd76378905c37da'
  },
  {
    id: 'malwarebazaar-ransomware-sample',
    name: 'MalwareBazaar Ransomware Sample Set',
    severity: 'critical',
    tags: ['malwarebazaar', 'ransomware', 'synced'],
    content:
      'sha256:31f1a95fb6514eb8de8df1ed6f9fef92d3f6fbc5c6cd4e8a4598b396c8f47840\n' +
      'sha256:98de0ca9d5a592abbf8f95ed18b17fd4659a132e4d9b3a20bc458cb03f995d99'
  }
];

function sanitizeFeed(raw: unknown): HashSourceFeed | null {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const source = raw as Record<string, unknown>;
  const id = String(source.id ?? '').trim();
  const name = String(source.name ?? '').trim();
  if (!id || !name) {
    return null;
  }

  return {
    id,
    name,
    severity: source.severity !== undefined ? String(source.severity ?? '').trim().toLowerCase() : undefined,
    tags: Array.isArray(source.tags)
      ? source.tags.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0)
      : undefined,
    content: source.content !== undefined ? String(source.content ?? '') : undefined,
    url: source.url !== undefined ? String(source.url ?? '').trim() : undefined
  };
}

function fetchText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res: any) => {
      const statusCode = Number(res?.statusCode ?? 0);
      if (statusCode < 200 || statusCode >= 300) {
        reject(new Error(`HTTP ${statusCode} while fetching ${url}`));
        res.resume();
        return;
      }

      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });

    req.on('error', (err: Error) => reject(err));
    req.setTimeout(15000, () => req.destroy(new Error(`Timeout fetching ${url}`)));
  });
}

async function fetchManifest(url: string): Promise<HashSourceFeed[]> {
  const text = await fetchText(url);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err: any) {
    throw new Error(`Invalid hashes manifest JSON: ${String(err?.message ?? err)}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error('Hashes manifest must be an array.');
  }

  const normalized = parsed
    .map((entry) => sanitizeFeed(entry))
    .filter((entry): entry is HashSourceFeed => entry !== null);

  if (normalized.length === 0) {
    throw new Error('Hashes manifest parsed zero valid feed entries.');
  }
  return normalized;
}

export async function loadMalwareBazaarSources(): Promise<HashSourceFeed[]> {
  const manifestUrl = String(process.env.XDR_HASHES_MALWAREBAZAAR_MANIFEST_URL ?? '').trim();
  if (!manifestUrl) {
    return BUILTIN_HASH_FEED;
  }

  try {
    return await fetchManifest(manifestUrl);
  } catch (_err) {
    return BUILTIN_HASH_FEED;
  }
}

function workerCountFor(total: number): number {
  if (total <= 1) {
    return 1;
  }
  const cpuCount = Number(os?.cpus?.()?.length ?? 1);
  const boundedCpu = Math.max(1, Math.min(cpuCount, 8));
  return Math.max(1, Math.min(total, boundedCpu));
}

async function loadOne(source: HashSourceFeed): Promise<{ id: string; name: string; ok: boolean; content?: string; error?: string }> {
  if (source.content && source.content.trim().length > 0) {
    return {
      id: source.id,
      name: source.name,
      ok: true,
      content: source.content
    };
  }

  const url = String(source.url ?? '').trim();
  if (!url) {
    return {
      id: source.id,
      name: source.name,
      ok: false,
      error: 'No hash content or URL provided.'
    };
  }

  try {
    const content = await fetchText(url);
    if (!content.trim()) {
      return {
        id: source.id,
        name: source.name,
        ok: false,
        error: 'Fetched hash feed is empty.'
      };
    }

    return {
      id: source.id,
      name: source.name,
      ok: true,
      content
    };
  } catch (err: any) {
    return {
      id: source.id,
      name: source.name,
      ok: false,
      error: String(err?.message ?? err)
    };
  }
}

export async function syncHashSourcesWithWorkerPool(sources: HashSourceFeed[]): Promise<HashSyncResult> {
  const normalized = sources.filter((entry) => entry && entry.id && entry.name);
  const workers = workerCountFor(normalized.length);
  const results: Array<{ id: string; name: string; ok: boolean; content?: string; error?: string }> = [];

  let cursor = 0;
  const runWorker = async (): Promise<void> => {
    while (true) {
      const idx = cursor;
      cursor += 1;
      if (idx >= normalized.length) {
        return;
      }
      const loaded = await loadOne(normalized[idx]);
      results.push(loaded);
    }
  };

  const jobs = Array.from({ length: workers }, () => runWorker());
  await Promise.all(jobs);

  results.sort((a, b) => a.id.localeCompare(b.id));
  const succeeded = results.filter((entry) => entry.ok).length;

  return {
    worker_count: workers,
    attempted: normalized.length,
    succeeded,
    failed: normalized.length - succeeded,
    items: results
  };
}