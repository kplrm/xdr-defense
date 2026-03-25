declare const require: any;

const fs = require('fs');
const path = require('path');

const DEFAULT_DATA_DIR = '/usr/share/opensearch-dashboards/data/xdr-defense';

function ensureDirectory(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
}

export function pluginDataDir(): string {
  const configured = String(process.env.XDR_DEFENSE_DATA_DIR ?? '').trim();
  const baseDir = configured || DEFAULT_DATA_DIR;
  ensureDirectory(baseDir);
  return baseDir;
}

export function resolvePluginDataPath(...segments: string[]): string {
  const target = path.join(pluginDataDir(), ...segments);
  ensureDirectory(path.dirname(target));
  return target;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function readJsonFile<T>(filePath: string, fallback: T): T {
  try {
    const raw = fs.readFileSync(filePath, { encoding: 'utf8' });
    return JSON.parse(raw) as T;
  } catch (_err) {
    return cloneJson(fallback);
  }
}

export function writeJsonFile(filePath: string, payload: unknown): void {
  const tmpFile = `${filePath}.tmp`;
  const serialized = `${JSON.stringify(payload, null, 2)}\n`;
  ensureDirectory(path.dirname(filePath));
  fs.writeFileSync(tmpFile, serialized, { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpFile, filePath);
  try {
    fs.chmodSync(filePath, 0o600);
  } catch (_err) {
    // Best effort only.
  }
}