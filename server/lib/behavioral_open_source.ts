declare const require: any;

const https = require('https');
const os = require('os');

export interface BehavioralSourceFeed {
  id: string;
  name: string;
  severity?: string;
  tags?: string[];
  content?: string;
  url?: string;
}

export interface BehavioralSyncResult {
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

const BUILTIN_SIGMA_FEED: BehavioralSourceFeed[] = [
  {
    id: 'sigmahq-encoded-powershell',
    name: 'SigmaHQ Encoded PowerShell',
    severity: 'high',
    tags: ['sigmahq', 'powershell', 'execution', 'synced'],
    content:
      'title: Suspicious Encoded PowerShell\n' +
      'id: 7a40f3d0-6cf6-45a8-8ce5-0f9dbfd7c001\n' +
      'status: stable\n' +
      'logsource:\n' +
      '  product: windows\n' +
      '  category: process_creation\n' +
      'detection:\n' +
      '  selection:\n' +
      '    CommandLine|contains: "-EncodedCommand"\n' +
      '  condition: selection\n'
  },
  {
    id: 'sigmahq-wget-curl-shell',
    name: 'SigmaHQ Download and Execute',
    severity: 'high',
    tags: ['sigmahq', 'linux', 'lolbin', 'synced'],
    content:
      'title: Download And Execute via Curl or Wget\n' +
      'id: 8b5113d2-dc8d-4a3d-8f79-b6fb6782a3f4\n' +
      'status: experimental\n' +
      'logsource:\n' +
      '  product: linux\n' +
      '  category: process_creation\n' +
      'detection:\n' +
      '  selection1:\n' +
      '    CommandLine|contains: "curl "\n' +
      '  selection2:\n' +
      '    CommandLine|contains: "wget "\n' +
      '  selection3:\n' +
      '    CommandLine|contains: "| sh"\n' +
      '  condition: (selection1 or selection2) and selection3\n'
  }
];

function sanitizeFeed(raw: unknown): BehavioralSourceFeed | null {
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

async function fetchManifest(url: string): Promise<BehavioralSourceFeed[]> {
  const text = await fetchText(url);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err: any) {
    throw new Error(`Invalid behavioral manifest JSON: ${String(err?.message ?? err)}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error('Behavioral manifest must be an array.');
  }

  const normalized = parsed
    .map((entry) => sanitizeFeed(entry))
    .filter((entry): entry is BehavioralSourceFeed => entry !== null);

  if (normalized.length === 0) {
    throw new Error('Behavioral manifest parsed zero valid feed entries.');
  }
  return normalized;
}

export async function loadSigmaSources(): Promise<BehavioralSourceFeed[]> {
  const manifestUrl = String(process.env.XDR_BEHAVIORAL_SIGMAHQ_MANIFEST_URL ?? '').trim();
  if (!manifestUrl) {
    return BUILTIN_SIGMA_FEED;
  }

  try {
    return await fetchManifest(manifestUrl);
  } catch (_err) {
    return BUILTIN_SIGMA_FEED;
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

async function loadOne(
  source: BehavioralSourceFeed
): Promise<{ id: string; name: string; ok: boolean; content?: string; error?: string }> {
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
      error: 'No behavioral rule content or URL provided.'
    };
  }

  try {
    const content = await fetchText(url);
    if (!content.trim()) {
      return {
        id: source.id,
        name: source.name,
        ok: false,
        error: 'Fetched behavioral feed is empty.'
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

export async function syncBehavioralSourcesWithWorkerPool(
  sources: BehavioralSourceFeed[]
): Promise<BehavioralSyncResult> {
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