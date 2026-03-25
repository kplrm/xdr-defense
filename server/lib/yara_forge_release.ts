declare const require: any;

const crypto = require('crypto');
const https = require('https');
const zlib = require('zlib');

const BufferCtor = (globalThis as any).Buffer;

export interface YaraForgeReleaseSource {
  id: string;
  name: string;
  content: string;
  severity: string;
  tags: string[];
  entry_path: string;
}

export interface YaraForgeReleaseBundle {
  release_tag: string;
  release_name: string;
  published_at?: string;
  asset_name: string;
  asset_updated_at?: string;
  sources: YaraForgeReleaseSource[];
}

interface GitHubReleaseAsset {
  name?: string;
  browser_download_url?: string;
  updated_at?: string;
}

interface GitHubReleaseResponse {
  tag_name?: string;
  name?: string;
  published_at?: string;
  assets?: GitHubReleaseAsset[];
}

interface ZipEntry {
  name: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

interface SplitRuleUnit {
  rule_name: string;
  content: string;
}

function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120);
}

function httpGetBuffer(url: string): Promise<Buffer> {
  return httpGetBufferWithRedirects(url, 5);
}

function httpGetBufferWithRedirects(url: string, remainingRedirects: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': 'xdr-defense'
        }
      },
      (res: any) => {
        const statusCode = Number(res?.statusCode ?? 0);
        if (statusCode >= 300 && statusCode < 400) {
          const location = String(res?.headers?.location ?? '').trim();
          if (!location) {
            reject(new Error(`HTTP ${statusCode} redirect without location while fetching ${url}`));
            res.resume();
            return;
          }
          if (remainingRedirects <= 0) {
            reject(new Error(`Too many redirects while fetching ${url}`));
            res.resume();
            return;
          }

          const nextUrl = new URL(location, url).toString();
          res.resume();
          httpGetBufferWithRedirects(nextUrl, remainingRedirects - 1).then(resolve).catch(reject);
          return;
        }

        if (statusCode < 200 || statusCode >= 300) {
          reject(new Error(`HTTP ${statusCode} while fetching ${url}`));
          res.resume();
          return;
        }

        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => resolve(BufferCtor.concat(chunks)));
      }
    );

    req.on('error', (err: Error) => reject(err));
    req.setTimeout(20000, () => req.destroy(new Error(`Timeout fetching ${url}`)));
  });
}

async function httpGetJson<T>(url: string): Promise<T> {
  const buffer = await httpGetBuffer(url);
  try {
    return JSON.parse(buffer.toString('utf8')) as T;
  } catch (err: any) {
    throw new Error(`Invalid JSON from ${url}: ${String(err?.message ?? err)}`);
  }
}

function findZipEntries(buffer: Buffer): ZipEntry[] {
  const endOfCentralDirectorySignature = 0x06054b50;
  const centralDirectorySignature = 0x02014b50;
  let eocdOffset = -1;

  for (let idx = buffer.length - 22; idx >= Math.max(0, buffer.length - 65557); idx -= 1) {
    if (buffer.readUInt32LE(idx) === endOfCentralDirectorySignature) {
      eocdOffset = idx;
      break;
    }
  }

  if (eocdOffset < 0) {
    throw new Error('Unable to locate ZIP central directory.');
  }

  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);
  const entries: ZipEntry[] = [];
  let cursor = centralDirectoryOffset;

  for (let index = 0; index < totalEntries; index += 1) {
    if (buffer.readUInt32LE(cursor) !== centralDirectorySignature) {
      throw new Error('Invalid ZIP central directory entry.');
    }

    const compressionMethod = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const uncompressedSize = buffer.readUInt32LE(cursor + 24);
    const fileNameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localHeaderOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.toString('utf8', cursor + 46, cursor + 46 + fileNameLength);

    entries.push({
      name,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      localHeaderOffset
    });

    cursor += 46 + fileNameLength + extraLength + commentLength;
  }

  return entries;
}

function extractZipEntry(buffer: Buffer, entry: ZipEntry): string {
  const localFileHeaderSignature = 0x04034b50;
  const headerOffset = entry.localHeaderOffset;
  if (buffer.readUInt32LE(headerOffset) !== localFileHeaderSignature) {
    throw new Error(`Invalid local ZIP header for ${entry.name}.`);
  }

  const fileNameLength = buffer.readUInt16LE(headerOffset + 26);
  const extraLength = buffer.readUInt16LE(headerOffset + 28);
  const dataOffset = headerOffset + 30 + fileNameLength + extraLength;
  const payload = buffer.subarray(dataOffset, dataOffset + entry.compressedSize);

  let output: Buffer;
  if (entry.compressionMethod === 0) {
    output = payload;
  } else if (entry.compressionMethod === 8) {
    output = zlib.inflateRawSync(payload);
  } else {
    throw new Error(`Unsupported ZIP compression method ${entry.compressionMethod} for ${entry.name}.`);
  }

  if (output.length !== entry.uncompressedSize) {
    throw new Error(`ZIP size mismatch for ${entry.name}.`);
  }

  return output.toString('utf8');
}

function extractRuleName(ruleContent: string): string {
  const match = ruleContent.match(/\brule\s+([A-Za-z0-9_]{1,128})\b/);
  if (match && match[1]) {
    return match[1];
  }
  return `rule_${crypto.createHash('sha1').update(ruleContent, 'utf8').digest('hex').slice(0, 10)}`;
}

function collectSharedDirectives(content: string): string[] {
  const directives: string[] = [];
  const seen = new Set<string>();

  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    const normalized = trimmed.replace(/\s+/g, ' ');
    if (!/^(import|include)\s+"[^"]+"\s*;?$/i.test(normalized)) {
      continue;
    }

    if (!seen.has(normalized)) {
      seen.add(normalized);
      directives.push(normalized);
    }
  }

  return directives;
}

function splitYaraRules(content: string): SplitRuleUnit[] {
  const units: SplitRuleUnit[] = [];
  if (!content.trim()) {
    return units;
  }

  const sharedDirectives = collectSharedDirectives(content);

  const declarationPattern = /^\s*(?:(?:private|global)\s+){0,2}rule\s+[A-Za-z0-9_]{1,128}\b.*$/gim;
  const starts: number[] = [];
  for (const match of content.matchAll(declarationPattern)) {
    if (typeof match.index === 'number') {
      starts.push(match.index);
    }
  }

  const pushRule = (start: number, endExclusive: number): void => {
    const raw = content.slice(start, endExclusive).trim();
    if (!raw) {
      return;
    }

    const ruleName = extractRuleName(raw);
    const composed = sharedDirectives.length > 0
      ? `${sharedDirectives.join('\n')}\n\n${raw}\n`
      : `${raw}\n`;
    units.push({
      rule_name: ruleName,
      content: composed
    });
  };

  for (let index = 0; index < starts.length; index += 1) {
    const start = starts[index];
    const end = index + 1 < starts.length ? starts[index + 1] : content.length;
    pushRule(start, end);
  }

  return units;
}

function buildStableRuleId(entryPath: string, ruleName: string, seen: Map<string, number>): string {
  const entryBase = entryPath.replace(/\.(yar|yara)$/i, '');
  const base = `forge-core-${slugify(`${entryBase}-${ruleName}`)}`;
  const count = seen.get(base) ?? 0;
  seen.set(base, count + 1);
  if (count === 0) {
    return base;
  }
  return `${base}-${count + 1}`;
}

export async function fetchLatestYaraForgeCoreRelease(): Promise<YaraForgeReleaseBundle> {
  const release = await httpGetJson<GitHubReleaseResponse>(
    'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest'
  );

  const releaseTag = String(release?.tag_name ?? '').trim();
  if (!releaseTag) {
    throw new Error('GitHub latest release response did not include a tag name.');
  }

  const asset = (Array.isArray(release.assets) ? release.assets : []).find(
    (entry) => String(entry?.name ?? '') === 'yara-forge-rules-core.zip'
  );
  if (!asset?.browser_download_url) {
    throw new Error('Latest YARA Forge release did not include yara-forge-rules-core.zip.');
  }

  const zipBuffer = await httpGetBuffer(String(asset.browser_download_url));
  const entries = findZipEntries(zipBuffer)
    .filter((entry) => entry.name.toLowerCase().endsWith('.yar') || entry.name.toLowerCase().endsWith('.yara'))
    .filter((entry) => !entry.name.endsWith('/'));

  if (entries.length === 0) {
    throw new Error('Latest YARA Forge core release asset did not contain any YARA files.');
  }

  const seenStableIds = new Map<string, number>();
  const flattenedSources = entries.flatMap((entry) => {
    const content = extractZipEntry(zipBuffer, entry);
    const splitRules = splitYaraRules(content);
    if (splitRules.length === 0) {
      return [];
    }

    return splitRules.map((ruleUnit) => {
      const stableId = buildStableRuleId(entry.name, ruleUnit.rule_name, seenStableIds);
      const checksum = crypto.createHash('sha256').update(ruleUnit.content, 'utf8').digest('hex').slice(0, 12);
      return {
        id: stableId,
        name: `YARA Forge Core ${ruleUnit.rule_name}`,
        content: ruleUnit.content,
        severity: 'high',
        tags: ['forge-core', 'github-release', releaseTag],
        entry_path: `${entry.name}#${ruleUnit.rule_name}`,
        checksum
      };
    });
  });

  if (flattenedSources.length === 0) {
    throw new Error('Latest YARA Forge core release did not contain parseable YARA rule blocks.');
  }

  const sources = flattenedSources
    .sort((a, b) => a.id.localeCompare(b.id))
    .map(({ checksum: _checksum, ...entry }) => entry);

  return {
    release_tag: releaseTag,
    release_name: String(release?.name ?? releaseTag),
    published_at: release?.published_at,
    asset_name: String(asset.name ?? 'yara-forge-rules-core.zip'),
    asset_updated_at: asset.updated_at,
    sources
  };
}