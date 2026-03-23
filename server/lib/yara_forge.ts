import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, createPrivateKey, sign } from 'crypto';

import { deleteArtifact, listArtifacts, upsertArtifact } from './store';

const yauzl = require('yauzl');

const DEFAULT_YARA_FORGE_CORE_URL =
  'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip';
const DEFAULT_DEV_SIGNING_PRIVATE_KEY_SEED_B64 =
  'e4Pe1VFSiHMBKxsh5ktKZpwvgQxE1yP27r01O1pUARo=';

export interface BundleRuleEntry {
  id: string;
  filename: string;
  content: string;
  sha256: string;
  enabled: boolean;
  source: 'managed';
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

export interface YaraForgeSyncMetadata {
  status?: 'idle' | 'downloading' | 'extracting' | 'processing' | 'completed' | 'failed';
  source?: string;
  sync_id?: string;
  started_at?: string;
  completed_at?: string;
  synced_at?: string;
  imported?: number;
  total_rules?: number;
  processed_rules?: number;
  version?: string;
  error?: string;
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

interface ImportedRuleFile {
  artifactID: string;
  originalPath: string;
  ruleName: string;
  content: string;
  sha256: string;
}

interface ForgeArtifactKeyParts {
  originalPath: string;
  ruleName: string;
}

let bundleVersionCounter = Math.floor(Date.now() / 1000);
let activeYaraForgeSyncPromise: Promise<{ imported: number; version: string; url: string; syncID: string }> | null = null;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8');

function concatUint8Arrays(chunks: readonly Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(totalLength);

  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return merged;
}

function baseDataDir(): string {
  return process.env.XDR_DEFENSE_DATA_DIR || path.resolve(process.cwd(), 'data', 'xdr-defense');
}

function forgeRulesDir(): string {
  return path.join(baseDataDir(), 'yara-forge', 'core');
}

function forgeSyncMetaPath(): string {
  return path.join(baseDataDir(), 'yara-forge', 'sync-meta.json');
}

function ensureForgeDirs(): void {
  fs.mkdirSync(forgeRulesDir(), { recursive: true });
}

function writeForgeSyncMeta(meta: YaraForgeSyncMetadata): void {
  ensureForgeDirs();
  fs.writeFileSync(forgeSyncMetaPath(), JSON.stringify(meta, null, 2) + '\n', 'utf8');
}

function sanitizeRuleName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^_+|_+$/g, '').toLowerCase();
}

function buildDeterministicForgeArtifactID(parts: ForgeArtifactKeyParts): string {
  const safeRuleName = sanitizeRuleName(parts.ruleName) || 'rule';
  const stableHash = createHash('sha256')
    .update(`${parts.originalPath}\n${parts.ruleName}`, 'utf8')
    .digest('hex')
    .slice(0, 12);
  return `yara-forge-${safeRuleName}-${stableHash}`;
}

function splitYaraRules(content: string): Array<{ ruleName: string; ruleText: string }> {
  const lines = content.split(/\r?\n/);
  const results: Array<{ ruleName: string; ruleText: string }> = [];

  let inRule = false;
  let braceDepth = 0;
  let currentRuleName = '';
  let currentLines: string[] = [];

  for (const line of lines) {
    if (!inRule) {
      const match = line.match(/^\s*(?:global\s+|private\s+)?rule\s+([A-Za-z0-9_]+)\b/);
      if (!match) {
        continue;
      }

      inRule = true;
      currentRuleName = match[1];
      currentLines = [line];
      const opens = (line.match(/\{/g) || []).length;
      const closes = (line.match(/\}/g) || []).length;
      braceDepth = opens - closes;

      if (braceDepth <= 0) {
        results.push({ ruleName: currentRuleName, ruleText: currentLines.join('\n').trim() + '\n' });
        inRule = false;
        braceDepth = 0;
        currentRuleName = '';
        currentLines = [];
      }
      continue;
    }

    currentLines.push(line);
    const opens = (line.match(/\{/g) || []).length;
    const closes = (line.match(/\}/g) || []).length;
    braceDepth += opens - closes;

    if (braceDepth <= 0) {
      results.push({
        ruleName: currentRuleName,
        ruleText: currentLines.join('\n').trim() + '\n',
      });
      inRule = false;
      braceDepth = 0;
      currentRuleName = '';
      currentLines = [];
    }
  }

  return results;
}

function computeSha256(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function parseSigningPrivateKey() {
  const encoded = String(process.env.XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64 ?? '').trim() || DEFAULT_DEV_SIGNING_PRIVATE_KEY_SEED_B64;
  if (!encoded) {
    return { ok: false, error: 'XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64 is not configured.' };
  }

  let raw: Buffer;
  try {
    raw = Buffer.from(encoded, 'base64');
  } catch {
    return { ok: false, error: 'Signing private key is not valid base64.' };
  }

  let seed = raw;
  if (raw.length === 64) {
    seed = raw.subarray(0, 32);
  }
  if (seed.length !== 32) {
    return { ok: false, error: `Signing private key must decode to 32-byte seed or 64-byte key, got ${raw.length} bytes.` };
  }

  try {
    const pkcs8Prefix = Uint8Array.from(Buffer.from('302e020100300506032b657004220420', 'hex'));
    const seedBytes = Uint8Array.from(seed);
    const pkcs8 = concatUint8Arrays([pkcs8Prefix, seedBytes]);
    return {
      ok: true,
      privateKey: createPrivateKey({
        key: Buffer.from(pkcs8),
        format: 'der',
        type: 'pkcs8',
      }),
    };
  } catch (err: any) {
    return { ok: false, error: `Unable to construct Ed25519 private key: ${String(err?.message ?? err)}` };
  }
}

async function downloadToTemp(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`YARA Forge download failed: HTTP ${response.status}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  const tempPath = path.join(os.tmpdir(), `yara-forge-core-${Date.now()}.zip`);
  fs.writeFileSync(tempPath, new Uint8Array(arrayBuffer));
  return tempPath;
}

async function extractZipRules(zipPath: string): Promise<ImportedRuleFile[]> {
  return new Promise((resolve, reject) => {
    const results: ImportedRuleFile[] = [];

    yauzl.open(zipPath, { lazyEntries: true }, (openErr: Error | null, zipFile: any) => {
      if (openErr || !zipFile) {
        reject(openErr || new Error('Unable to open zip file'));
        return;
      }

      zipFile.readEntry();
      zipFile.on('entry', (entry: any) => {
        const entryName = String(entry.fileName || '');
        if (/\/$/.test(entryName) || !/\.(yar|yara)$/i.test(entryName)) {
          zipFile.readEntry();
          return;
        }

        zipFile.openReadStream(entry, (streamErr: Error | null, readStream: any) => {
          if (streamErr || !readStream) {
            reject(streamErr || new Error(`Unable to read zip entry ${entryName}`));
            return;
          }

          const chunks: Uint8Array[] = [];
          readStream.on('data', (chunk: Uint8Array) => chunks.push(chunk));
          readStream.once('error', reject);
          readStream.on('end', () => {
            const content = textDecoder.decode(concatUint8Arrays(chunks));
            const rules = splitYaraRules(content);

            if (rules.length === 0) {
              const fallbackRuleName = path.basename(entryName).replace(/\.(yar|yara)$/i, '');
              const artifactID = buildDeterministicForgeArtifactID({
                originalPath: entryName,
                ruleName: fallbackRuleName,
              });
              results.push({
                artifactID,
                originalPath: entryName,
                ruleName: fallbackRuleName,
                content,
                sha256: computeSha256(content),
              });
            } else {
              for (const parsedRule of rules) {
                const artifactID = buildDeterministicForgeArtifactID({
                  originalPath: entryName,
                  ruleName: parsedRule.ruleName,
                });
                results.push({
                  artifactID,
                  originalPath: entryName,
                  ruleName: parsedRule.ruleName,
                  content: parsedRule.ruleText,
                  sha256: computeSha256(parsedRule.ruleText),
                });
              }
            }
            zipFile.readEntry();
          });
        });
      });

      zipFile.once('end', () => resolve(results));
      zipFile.once('error', reject);
    });
  });
}

export async function syncYaraForgeCore(syncID = `${Date.now()}`): Promise<{ imported: number; version: string; url: string; syncID: string }> {
  ensureForgeDirs();
  const url = process.env.XDR_DEFENSE_YARA_FORGE_CORE_URL || DEFAULT_YARA_FORGE_CORE_URL;
  const startedAt = new Date().toISOString();
  writeForgeSyncMeta({
    status: 'downloading',
    source: url,
    sync_id: syncID,
    started_at: startedAt,
    imported: 0,
    processed_rules: 0,
  });
  const tempZipPath = await downloadToTemp(url);

  try {
    writeForgeSyncMeta({
      status: 'extracting',
      source: url,
      sync_id: syncID,
      started_at: startedAt,
      imported: 0,
      processed_rules: 0,
    });

    const importedRules = await extractZipRules(tempZipPath);
    const syncVersion = new Date().toISOString();
    const importedIDs = new Set(importedRules.map((ruleFile) => ruleFile.artifactID));
    let processedRules = 0;

    writeForgeSyncMeta({
      status: 'processing',
      source: url,
      sync_id: syncID,
      started_at: startedAt,
      version: syncVersion,
      total_rules: importedRules.length,
      imported: 0,
      processed_rules: 0,
    });

    const existingArtifacts = await listArtifacts();
    const existingForgeArtifactsByID = existingArtifacts
      .filter((artifact) => artifact.id.startsWith('yara-forge-'))
      .reduce<Record<string, (typeof existingArtifacts)[number]>>((acc, artifact) => {
        acc[artifact.id] = artifact;
        return acc;
      }, {});
    const staleArtifacts = existingArtifacts.filter(
      (artifact) => artifact.id.startsWith('yara-forge-') && !importedIDs.has(artifact.id)
    );

    for (const staleArtifact of staleArtifacts) {
      fs.rmSync(getYaraForgeRuleFilePath(staleArtifact.id), { force: true });
      await deleteArtifact(staleArtifact.id);
    }

    const configuredConcurrency = Number(process.env.XDR_DEFENSE_YARA_FORGE_SYNC_CONCURRENCY || '0');
    const cpuCount =
      typeof (os as any).availableParallelism === 'function'
        ? Number((os as any).availableParallelism())
        : Math.max(1, os.cpus().length);
    const defaultConcurrency = Math.max(2, cpuCount);
    const boundedConcurrency = Math.max(
      1,
      Math.min(
        importedRules.length || 1,
        32,
        Number.isFinite(configuredConcurrency) && configuredConcurrency > 0
          ? Math.floor(configuredConcurrency)
          : defaultConcurrency
      )
    );

    let nextRuleIndex = 0;
    const processRuleFile = async (ruleFile: ImportedRuleFile) => {
      const outputPath = path.join(forgeRulesDir(), `${ruleFile.artifactID}.yar`);
      const checksum = `sha256:${ruleFile.sha256}`;
      const description = `Imported from YARA Forge Core (${ruleFile.ruleName}) from ${ruleFile.originalPath}`;
      const existingArtifact = existingForgeArtifactsByID[ruleFile.artifactID];
      const shouldWriteRuleFile =
        !existingArtifact || existingArtifact.checksum !== checksum || !fs.existsSync(outputPath);

      if (shouldWriteRuleFile) {
        fs.writeFileSync(outputPath, ruleFile.content, 'utf8');
      }

      const requiresArtifactUpdate =
        !existingArtifact ||
        existingArtifact.checksum !== checksum ||
        existingArtifact.sourceUrl !== url ||
        existingArtifact.description !== description ||
        existingArtifact.enabled !== true;

      if (requiresArtifactUpdate) {
        await upsertArtifact({
          id: ruleFile.artifactID,
          type: 'yara',
          version: syncVersion,
          checksum,
          enabled: true,
          sourceUrl: url,
          description,
        });
      }

      processedRules += 1;
      writeForgeSyncMeta({
        status: 'processing',
        source: url,
        sync_id: syncID,
        started_at: startedAt,
        version: syncVersion,
        total_rules: importedRules.length,
        imported: processedRules,
        processed_rules: processedRules,
      });
    };

    const workers = Array.from({ length: boundedConcurrency }, async () => {
      while (true) {
        const currentIndex = nextRuleIndex;
        nextRuleIndex += 1;
        if (currentIndex >= importedRules.length) {
          return;
        }
        await processRuleFile(importedRules[currentIndex]);
      }
    });

    await Promise.all(workers);

    writeForgeSyncMeta({
      status: 'completed',
      source: url,
      sync_id: syncID,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      synced_at: syncVersion,
      version: syncVersion,
      total_rules: importedRules.length,
      imported: importedRules.length,
      processed_rules: importedRules.length,
    });

    return { imported: importedRules.length, version: syncVersion, url, syncID };
  } catch (err: any) {
    writeForgeSyncMeta({
      status: 'failed',
      source: url,
      sync_id: syncID,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      error: String(err?.message ?? err),
    });
    throw err;
  } finally {
    fs.rmSync(tempZipPath, { force: true });
  }
}

export function startYaraForgeCoreSync(): { started: boolean; syncID?: string; metadata: YaraForgeSyncMetadata } {
  const current = getYaraForgeSyncMetadata();
  if (activeYaraForgeSyncPromise) {
    return {
      started: false,
      syncID: current.sync_id,
      metadata: current,
    };
  }

  const syncID = `${Date.now()}`;
  activeYaraForgeSyncPromise = syncYaraForgeCore(syncID).finally(() => {
    activeYaraForgeSyncPromise = null;
  });

  return {
    started: true,
    syncID,
    metadata: getYaraForgeSyncMetadata(),
  };
}

export function getYaraForgeRuleFilePath(artifactID: string): string {
  return path.join(forgeRulesDir(), `${artifactID}.yar`);
}

export function getYaraForgeSyncMetadata(): YaraForgeSyncMetadata {
  try {
    const content = fs.readFileSync(forgeSyncMetaPath(), 'utf8');
    return JSON.parse(content);
  } catch {
    return { status: 'idle', imported: 0, processed_rules: 0 };
  }
}

export async function buildSignedYaraBundle(policyID: string): Promise<SignedBundleResponse> {
  const keyResult = parseSigningPrivateKey();
  if (!keyResult.ok || !keyResult.privateKey) {
    throw new Error(keyResult.error || 'Signing key is unavailable.');
  }

  const artifacts = await listArtifacts(policyID);
  const yaraArtifacts = artifacts.filter((artifact) => artifact.type === 'yara' && artifact.enabled);
  const rules: BundleRuleEntry[] = [];
  const missingFiles: string[] = [];

  for (const artifact of yaraArtifacts) {
    const filePath = getYaraForgeRuleFilePath(artifact.id);
    if (!fs.existsSync(filePath)) {
      missingFiles.push(artifact.id);
      continue;
    }
    const content = fs.readFileSync(filePath, 'utf8');
    rules.push({
      id: artifact.id,
      filename: `${artifact.id}.yar`,
      content,
      sha256: computeSha256(content),
      enabled: true,
      source: 'managed',
      updatedAt: artifact.updatedAt,
    });
  }

  // If registered artifacts exist but ALL or most rule files are missing, the
  // data directory has likely been cleared (e.g. container rebuilt without a
  // volume mount).  Returning an empty bundle would silently wipe all agent
  // rules, so we surface a hard error that prompts the operator to re-sync.
  if (missingFiles.length > 0 && rules.length === 0 && yaraArtifacts.length > 0) {
    throw new Error(
      `Bundle would be empty: ${yaraArtifacts.length} artifacts registered but all ` +
      `rule files are missing from disk (e.g. after container rebuild). ` +
      `Run "Sync YARA Forge Core" to regenerate rule files.`
    );
  }

  const payload: BundlePayload = {
    manifest_version: 1,
    policy_id: policyID,
    bundle_version: bundleVersionCounter++,
    generated_at: new Date().toISOString(),
    signing_alg: 'ed25519',
    rules,
    active_checksums: rules.map((rule) => rule.sha256).sort((a, b) => a.localeCompare(b)),
  };

  const payloadBytes = textEncoder.encode(JSON.stringify(payload));
  const signature = sign(null, payloadBytes, keyResult.privateKey);

  return {
    ...payload,
    signature_base64: signature.toString('base64'),
    signed_payload_base64: Buffer.from(payloadBytes).toString('base64'),
  };
}