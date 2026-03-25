declare const require: any;

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const BufferCtor = (globalThis as any).Buffer;

export type SigningKeySource = 'env' | 'file' | 'generated';

interface KeyMaterial {
  seed: any;
  source: SigningKeySource;
}

interface SigningKeySnapshot {
  privateKey: any;
  public_key_b64: string;
  key_id: string;
  source: SigningKeySource;
}

export interface SigningPrivateKeyResult {
  ok: boolean;
  privateKey?: any;
  source?: SigningKeySource;
  key_id?: string;
  error?: string;
}

export interface SigningPublicKeyResult {
  ok: boolean;
  public_key_b64?: string;
  source?: SigningKeySource;
  key_id?: string;
  error?: string;
}

const DEFAULT_SIGNING_PRIVATE_KEY_FILE =
  '/usr/share/opensearch-dashboards/data/xdr-defense/signing_private_key.b64';

const generatedInProcessPaths = new Set<string>();

function signingPrivateKeyFilePath(): string {
  const configured = String(process.env.XDR_DEFENSE_SIGNING_PRIVATE_KEY_FILE ?? '').trim();
  return configured || DEFAULT_SIGNING_PRIVATE_KEY_FILE;
}

function parseSeedFromBase64(encodedRaw: string, label: string): { ok: boolean; seed?: any; error?: string } {
  const encoded = encodedRaw.trim();
  if (!encoded) {
    return { ok: false, error: `${label} is empty.` };
  }

  let raw: any;
  try {
    raw = BufferCtor.from(encoded, 'base64');
  } catch (_err) {
    return { ok: false, error: `${label} is not valid base64.` };
  }

  if (!raw || !raw.length) {
    return { ok: false, error: `${label} decode produced empty bytes.` };
  }

  let seed = raw;
  if (raw.length === 64) {
    seed = raw.subarray(0, 32);
  }

  if (seed.length !== 32) {
    return {
      ok: false,
      error: `${label} must decode to 32-byte seed or 64-byte private key, got ${raw.length} bytes.`
    };
  }

  return { ok: true, seed };
}

function ensureFilePermissions(filePath: string): void {
  try {
    fs.chmodSync(filePath, 0o600);
  } catch (_err) {
    // Best effort: leave existing permissions unchanged if chmod fails.
  }
}

function persistGeneratedSeed(filePath: string, seed: any): {
  ok: boolean;
  created?: boolean;
  error?: string;
} {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(filePath, `${seed.toString('base64')}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    });
    ensureFilePermissions(filePath);
    return { ok: true, created: true };
  } catch (err: any) {
    if (err?.code === 'EEXIST') {
      return { ok: true, created: false };
    }
    return {
      ok: false,
      error: `Failed to persist generated signing key to ${filePath}: ${String(err?.message ?? err)}`
    };
  }
}

function loadSeedFromFile(filePath: string): { ok: boolean; seed?: any; source?: SigningKeySource; error?: string } {
  try {
    const encoded = String(fs.readFileSync(filePath, { encoding: 'utf8' }) ?? '').trim();
    ensureFilePermissions(filePath);
    const parsed = parseSeedFromBase64(encoded, `Signing private key file (${filePath})`);
    if (!parsed.ok || !parsed.seed) {
      return { ok: false, error: parsed.error };
    }
    return {
      ok: true,
      seed: parsed.seed,
      source: generatedInProcessPaths.has(filePath) ? 'generated' : 'file'
    };
  } catch (err: any) {
    if (err?.code !== 'ENOENT') {
      return {
        ok: false,
        error: `Failed to read signing private key file (${filePath}): ${String(err?.message ?? err)}`
      };
    }
  }

  const generatedSeed = crypto.randomBytes(32);
  const persisted = persistGeneratedSeed(filePath, generatedSeed);
  if (!persisted.ok) {
    return { ok: false, error: persisted.error };
  }
  if (persisted.created) {
    generatedInProcessPaths.add(filePath);
  }

  try {
    const encoded = String(fs.readFileSync(filePath, { encoding: 'utf8' }) ?? '').trim();
    ensureFilePermissions(filePath);
    const parsed = parseSeedFromBase64(encoded, `Signing private key file (${filePath})`);
    if (!parsed.ok || !parsed.seed) {
      return { ok: false, error: parsed.error };
    }
    return { ok: true, seed: parsed.seed, source: persisted.created ? 'generated' : 'file' };
  } catch (err: any) {
    return {
      ok: false,
      error: `Failed to read persisted signing key after generation (${filePath}): ${String(err?.message ?? err)}`
    };
  }
}

function resolveSeedMaterial(): { ok: boolean; material?: KeyMaterial; error?: string } {
  const envEncoded = String(process.env.XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64 ?? '').trim();
  if (envEncoded) {
    const parsed = parseSeedFromBase64(envEncoded, 'XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64');
    if (!parsed.ok || !parsed.seed) {
      return { ok: false, error: parsed.error };
    }
    return { ok: true, material: { seed: parsed.seed, source: 'env' } };
  }

  const filePath = signingPrivateKeyFilePath();
  const fileSeed = loadSeedFromFile(filePath);
  if (!fileSeed.ok || !fileSeed.seed || !fileSeed.source) {
    return { ok: false, error: fileSeed.error ?? 'Unable to resolve signing private key from file.' };
  }

  return {
    ok: true,
    material: {
      seed: fileSeed.seed,
      source: fileSeed.source
    }
  };
}

function buildSnapshot(material: KeyMaterial): { ok: boolean; snapshot?: SigningKeySnapshot; error?: string } {
  try {
    const pkcs8Prefix = BufferCtor.from('302e020100300506032b657004220420', 'hex');
    const pkcs8 = BufferCtor.concat([pkcs8Prefix, material.seed]);
    const privateKey = crypto.createPrivateKey({
      key: pkcs8,
      format: 'der',
      type: 'pkcs8'
    });
    const publicKey = crypto.createPublicKey(privateKey);
    const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
    const publicKeyRaw = publicKeyDer.subarray(publicKeyDer.length - 32);
    const publicKeyB64 = publicKeyRaw.toString('base64');
    const keyId = crypto.createHash('sha256').update(publicKeyRaw).digest('hex').slice(0, 16);

    return {
      ok: true,
      snapshot: {
        privateKey,
        public_key_b64: publicKeyB64,
        key_id: keyId,
        source: material.source
      }
    };
  } catch (err: any) {
    return {
      ok: false,
      error: `Unable to construct Ed25519 signing key pair: ${String(err?.message ?? err)}`
    };
  }
}

function resolveSigningSnapshot(): { ok: boolean; snapshot?: SigningKeySnapshot; error?: string } {
  const material = resolveSeedMaterial();
  if (!material.ok || !material.material) {
    return { ok: false, error: material.error ?? 'Unable to resolve signing key material.' };
  }

  const snapshot = buildSnapshot(material.material);
  if (!snapshot.ok || !snapshot.snapshot) {
    return { ok: false, error: snapshot.error ?? 'Unable to build signing key snapshot.' };
  }

  return { ok: true, snapshot: snapshot.snapshot };
}

export function getSigningPrivateKey(): SigningPrivateKeyResult {
  const resolved = resolveSigningSnapshot();
  if (!resolved.ok || !resolved.snapshot) {
    return { ok: false, error: resolved.error ?? 'Signing key is unavailable.' };
  }

  return {
    ok: true,
    privateKey: resolved.snapshot.privateKey,
    source: resolved.snapshot.source,
    key_id: resolved.snapshot.key_id
  };
}

export function getSigningPublicKey(): SigningPublicKeyResult {
  const resolved = resolveSigningSnapshot();
  if (!resolved.ok || !resolved.snapshot) {
    return { ok: false, error: resolved.error ?? 'Signing key is unavailable.' };
  }

  return {
    ok: true,
    public_key_b64: resolved.snapshot.public_key_b64,
    source: resolved.snapshot.source,
    key_id: resolved.snapshot.key_id
  };
}
