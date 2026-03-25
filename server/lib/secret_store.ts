declare const require: any;

const crypto = require('crypto');
const fs = require('fs');
const BufferCtor = (globalThis as any).Buffer;

import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';

interface EncryptedSecretRecord {
  iv_b64: string;
  auth_tag_b64: string;
  cipher_text_b64: string;
  updated_at: string;
}

interface SecretState {
  version: 1;
  secrets: Record<string, EncryptedSecretRecord>;
}

const SECRET_STATE_FILE = resolvePluginDataPath('secrets', 'encrypted_secrets.json');
const DEFAULT_SECRET_KEY_FILE = resolvePluginDataPath('secrets', 'encryption_key.b64');
const MALWARE_BAZAAR_SECRET_NAME = 'malwarebazaar_api_key';

function isoNow(): string {
  return new Date().toISOString();
}

function defaultSecretState(): SecretState {
  return {
    version: 1,
    secrets: {}
  };
}

function encryptionKeyFilePath(): string {
  const configured = String(process.env.XDR_DEFENSE_SECRET_ENCRYPTION_KEY_FILE ?? '').trim();
  return configured || DEFAULT_SECRET_KEY_FILE;
}

function parseKeyMaterial(encodedRaw: string, label: string): Buffer {
  const encoded = encodedRaw.trim();
  if (!encoded) {
    throw new Error(`${label} is empty.`);
  }

  const decoded = BufferCtor.from(encoded, 'base64');
  if (decoded.length !== 32) {
    throw new Error(`${label} must decode to exactly 32 bytes, got ${decoded.length}.`);
  }
  return decoded;
}

function ensureKeyPermissions(filePath: string): void {
  try {
    fs.chmodSync(filePath, 0o600);
  } catch (_err) {
    // Best effort only.
  }
}

function resolveEncryptionKey(): Buffer {
  const envKey = String(process.env.XDR_DEFENSE_SECRET_ENCRYPTION_KEY_B64 ?? '').trim();
  if (envKey) {
    return parseKeyMaterial(envKey, 'XDR_DEFENSE_SECRET_ENCRYPTION_KEY_B64');
  }

  const filePath = encryptionKeyFilePath();
  try {
    const encoded = String(fs.readFileSync(filePath, { encoding: 'utf8' }) ?? '').trim();
    ensureKeyPermissions(filePath);
    return parseKeyMaterial(encoded, `Secret encryption key file (${filePath})`);
  } catch (err: any) {
    if (err?.code !== 'ENOENT') {
      throw new Error(`Failed to read secret encryption key file (${filePath}): ${String(err?.message ?? err)}`);
    }
  }

  const generated = crypto.randomBytes(32);
  fs.writeFileSync(filePath, `${generated.toString('base64')}\n`, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx'
  });
  ensureKeyPermissions(filePath);
  return generated;
}

function loadSecretState(): SecretState {
  const raw = readJsonFile<SecretState>(SECRET_STATE_FILE, defaultSecretState());
  return {
    version: 1,
    secrets: raw?.secrets && typeof raw.secrets === 'object' ? raw.secrets : {}
  };
}

function saveSecretState(state: SecretState): void {
  writeJsonFile(SECRET_STATE_FILE, state);
}

function encryptSecret(secretValue: string): EncryptedSecretRecord {
  const key = resolveEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = BufferCtor.concat([cipher.update(secretValue, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    iv_b64: iv.toString('base64'),
    auth_tag_b64: authTag.toString('base64'),
    cipher_text_b64: encrypted.toString('base64'),
    updated_at: isoNow()
  };
}

function decryptSecret(record: EncryptedSecretRecord): string {
  const key = resolveEncryptionKey();
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    BufferCtor.from(String(record.iv_b64 ?? ''), 'base64')
  );
  decipher.setAuthTag(BufferCtor.from(String(record.auth_tag_b64 ?? ''), 'base64'));
  const decrypted = BufferCtor.concat([
    decipher.update(BufferCtor.from(String(record.cipher_text_b64 ?? ''), 'base64')),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

export function setMalwareBazaarApiKey(apiKeyRaw: string): { configured: boolean; updated_at: string } {
  const apiKey = String(apiKeyRaw ?? '').trim();
  if (!apiKey) {
    throw new Error('MalwareBazaar API key cannot be empty.');
  }

  const state = loadSecretState();
  const record = encryptSecret(apiKey);
  state.secrets[MALWARE_BAZAAR_SECRET_NAME] = record;
  saveSecretState(state);
  return {
    configured: true,
    updated_at: record.updated_at
  };
}

export function getMalwareBazaarApiKey(): string | null {
  const state = loadSecretState();
  const record = state.secrets[MALWARE_BAZAAR_SECRET_NAME];
  if (!record) {
    return null;
  }
  return decryptSecret(record);
}

export function getMalwareBazaarApiKeyStatus(): { configured: boolean; updated_at?: string } {
  const state = loadSecretState();
  const record = state.secrets[MALWARE_BAZAAR_SECRET_NAME];
  if (!record) {
    return { configured: false };
  }
  return {
    configured: true,
    updated_at: record.updated_at
  };
}