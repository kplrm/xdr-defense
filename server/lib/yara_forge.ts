declare const require: any;

const os = require('os');
const https = require('https');

export interface ForgeCoreSource {
  id: string;
  name: string;
  severity?: string;
  tags?: string[];
  content?: string;
  url?: string;
}

export interface ForgeSyncResult {
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

const BUILTIN_FORGE_CORE_RULES: ForgeCoreSource[] = [
  {
    id: 'forge-core-encoded-powershell',
    name: 'Forge Core Encoded PowerShell',
    severity: 'high',
    tags: ['forge-core', 'powershell', 'execution'],
    content:
      'rule forge_core_encoded_powershell {\n' +
      '  strings:\n' +
      '    $encoded = "-EncodedCommand" nocase\n' +
      '    $b64 = /[A-Za-z0-9+\\/=]{40,}/\n' +
      '  condition:\n' +
      '    $encoded and $b64\n' +
      '}'
  },
  {
    id: 'forge-core-ransom-note',
    name: 'Forge Core Ransom Note',
    severity: 'critical',
    tags: ['forge-core', 'ransomware', 'files'],
    content:
      'rule forge_core_ransom_note {\n' +
      '  strings:\n' +
      '    $n1 = "all your files are encrypted" nocase\n' +
      '    $n2 = "decrypt your files" nocase\n' +
      '  condition:\n' +
      '    any of ($n*)\n' +
      '}'
  },
  {
    id: 'forge-core-wget-curl-exec',
    name: 'Forge Core Download And Execute',
    severity: 'high',
    tags: ['forge-core', 'execution', 'lolbin'],
    content:
      'rule forge_core_download_and_execute {\n' +
      '  strings:\n' +
      '    $w = "wget " nocase\n' +
      '    $c = "curl " nocase\n' +
      '    $pipe = "| sh" nocase\n' +
      '  condition:\n' +
      '    ($w or $c) and $pipe\n' +
      '}'
  }
];

function sanitizeSource(raw: unknown): ForgeCoreSource | null {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const source = raw as Record<string, unknown>;
  const id = String(source.id ?? '').trim();
  const name = String(source.name ?? '').trim();
  if (!id || !name) {
    return null;
  }

  const content = source.content !== undefined ? String(source.content ?? '') : undefined;
  const url = source.url !== undefined ? String(source.url ?? '').trim() : undefined;
  const severity = source.severity !== undefined ? String(source.severity ?? '').trim().toLowerCase() : undefined;
  const tags = Array.isArray(source.tags)
    ? source.tags.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0)
    : undefined;

  return {
    id,
    name,
    severity,
    tags,
    content,
    url
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
      res.on('end', () => {
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
    });

    req.on('error', (err: Error) => {
      reject(err);
    });

    req.setTimeout(15000, () => {
      req.destroy(new Error(`Timeout fetching ${url}`));
    });
  });
}

async function fetchRemoteManifest(url: string): Promise<ForgeCoreSource[]> {
  const raw = await fetchText(url);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`Invalid Forge manifest JSON: ${String(err?.message ?? err)}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error('Forge manifest must be an array.');
  }

  const sources = parsed
    .map((entry) => sanitizeSource(entry))
    .filter((entry): entry is ForgeCoreSource => entry !== null);

  if (sources.length === 0) {
    throw new Error('Forge manifest parsed zero valid sources.');
  }

  return sources;
}

export async function loadForgeCoreSources(): Promise<ForgeCoreSource[]> {
  const manifestUrl = String(process.env.XDR_YARA_FORGE_CORE_MANIFEST_URL ?? '').trim();
  if (!manifestUrl) {
    return BUILTIN_FORGE_CORE_RULES;
  }

  try {
    return await fetchRemoteManifest(manifestUrl);
  } catch (_err) {
    // Fall back to a local built-in catalog to keep sync usable when remote fetch is down.
    return BUILTIN_FORGE_CORE_RULES;
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

async function loadOne(source: ForgeCoreSource): Promise<{ id: string; name: string; ok: boolean; content?: string; error?: string }> {
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
      error: 'No rule content or URL provided.'
    };
  }

  try {
    const content = await fetchText(url);
    if (!content.trim()) {
      return {
        id: source.id,
        name: source.name,
        ok: false,
        error: 'Fetched rule content is empty.'
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

export async function syncForgeCoreWithWorkerPool(
  sources: ForgeCoreSource[]
): Promise<ForgeSyncResult> {
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
      const source = normalized[idx];
      const loaded = await loadOne(source);
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
