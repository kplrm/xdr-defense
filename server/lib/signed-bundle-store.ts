// Signed YARA bundle types and storage

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface RuleSource {
  id: string;
  name: string;
  description: string;
  source: 'builtin' | 'custom';
  enabled: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  file_path: string;
  checksum_sha256: string;
  tags: string[];
  module_scope: string[];
  mitre_tactics: string[];
  status: 'draft' | 'validated' | 'active';
  custom_metadata?: Record<string, unknown>;
}

export interface RuleManifest {
  version: string;
  created_at: string;
  rule_sources: RuleSource[];
  enforcement_summary: {
    total_rules: number;
    enabled_rules: number;
    validation_errors: string[];
  };
}

export interface SignedYaraBundle {
  manifest: RuleManifest;
  bundle_signature: string; // base64 ed25519 signature
  public_key_cert: string; // PEM format public key
}

export interface BundleResponse {
  bundle: SignedYaraBundle;
  version: string;
  download_url: string;
}

// Storage layer for rules and bundles
export class SignedBundleStore {
  private rulesDir: string;
  private bundleDir: string;
  private privateKeyPath: string;
  private rules: Map<string, RuleSource>;
  private currentBundleVersion: string;

  constructor(rulesDir: string, bundleDir: string, privateKeyPath: string) {
    this.rulesDir = rulesDir;
    this.bundleDir = bundleDir;
    this.privateKeyPath = privateKeyPath;
    this.rules = new Map();
    this.currentBundleVersion = '';

    // Ensure directories exist
    fs.mkdirSync(this.bundleDir, { recursive: true });
    fs.mkdirSync(this.rulesDir, { recursive: true });
  }

  // Generate next bundle version: YYYY.MM.DD.SEQUENCE
  private generateBundleVersion(): string {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const date = `${year}.${month}.${day}`;

    // Check existing bundles for today's date and increment sequence
    let sequence = 1;
    const prefix = `${date}.`;
    const bundleList = fs.readdirSync(this.bundleDir).filter(f => f.startsWith(prefix));
    if (bundleList.length > 0) {
      const latest = bundleList.sort().pop()!;
      const match = latest.match(/\.(\d+)\.json$/);
      if (match) {
        sequence = parseInt(match[1], 10) + 1;
      }
    }

    return `${date}.${sequence}`;
  }

  // Add or update a rule
  addOrUpdateRule(rule: RuleSource): void {
    if (!rule.checksum_sha256) {
      throw new Error(`Rule ${rule.id}: checksum_sha256 is required`);
    }
    this.rules.set(rule.id, {
      ...rule,
      status: 'draft'
    });
  }

  // Delete a custom rule (builtin rules can only be disabled)
  deleteRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      return false;
    }
    if (rule.source === 'builtin') {
      throw new Error(`Cannot delete builtin rule ${ruleId}; disable it instead`);
    }
    this.rules.delete(ruleId);
    return true;
  }

  // Toggle rule enabled state
  toggleRule(ruleId: string, enabled: boolean): void {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      throw new Error(`Rule ${ruleId} not found`);
    }
    rule.enabled = enabled;
  }

  // Validate a rule (syntax check via YARA-X compiler)
  async validateRule(ruleId: string): Promise<{ valid: boolean; error?: string }> {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      return { valid: false, error: 'Rule not found' };
    }

    const ruleFilePath = path.join(this.rulesDir, rule.file_path);
    if (!fs.existsSync(ruleFilePath)) {
      return { valid: false, error: `Rule file not found: ${ruleFilePath}` };
    }

    // TODO: Call YARA-X compiler (async, via child process or WASM)
    // For now, basic file check
    try {
      const content = fs.readFileSync(ruleFilePath, 'utf-8');
      if (!content.trim()) {
        return { valid: false, error: 'Rule file is empty' };
      }
      rule.status = 'validated';
      return { valid: true };
    } catch (err: any) {
      return { valid: false, error: err.message };
    }
  }

  // Build and sign bundle
  async buildAndSignBundle(): Promise<SignedYaraBundle> {
    const enabledRules = Array.from(this.rules.values()).filter(r => r.enabled);
    const validationErrors: string[] = [];

    // Validate all enabled rules
    for (const rule of enabledRules) {
      const validation = await this.validateRule(rule.id);
      if (!validation.valid) {
        validationErrors.push(`${rule.id}: ${validation.error}`);
      }
    }

    // If validation errors exist, fail the bundle
    if (validationErrors.length > 0) {
      throw new Error(`Bundle validation failed:\n${validationErrors.join('\n')}`);
    }

    const version = this.generateBundleVersion();
    this.currentBundleVersion = version;

    const manifest: RuleManifest = {
      version,
      created_at: new Date().toISOString(),
      rule_sources: enabledRules,
      enforcement_summary: {
        total_rules: this.rules.size,
        enabled_rules: enabledRules.length,
        validation_errors: validationErrors
      }
    };

    // Sign the manifest
    const manifestJson = JSON.stringify(manifest, null, 2);
    const bundle = this.signManifest(manifestJson);

    // Save bundle to disk
    const bundlePath = path.join(this.bundleDir, `${version}.json`);
    fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));

    return bundle;
  }

  // Sign manifest using private key
  private signManifest(manifestJson: string): SignedYaraBundle {
    // Read private key (in production, use secure key management)
    if (!fs.existsSync(this.privateKeyPath)) {
      throw new Error(`Private key not found at ${this.privateKeyPath}`);
    }

    const privateKeyPem = fs.readFileSync(this.privateKeyPath, 'utf-8');
    
    // Sign using Node.js crypto
    const sign = crypto.createSign('sha256');
    sign.update(manifestJson);
    const signature = sign.sign(privateKeyPem, 'base64');

    // Extract public key from private key
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const publicKey = crypto.createPublicKey(privateKey);
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();

    return {
      manifest: JSON.parse(manifestJson),
      bundle_signature: signature,
      public_key_cert: publicKeyPem
    };
  }

  // Verify bundle signature (used by agent and UI)
  static verifyBundleSignature(bundle: SignedYaraBundle): boolean {
    try {
      const manifestJson = JSON.stringify(bundle.manifest, null, 2);
      const publicKey = crypto.createPublicKey({
        key: bundle.public_key_cert,
        format: 'pem'
      });

      const verify = crypto.createVerify('sha256');
      verify.update(manifestJson);
      return verify.verify(publicKey, bundle.bundle_signature, 'base64');
    } catch (err) {
      return false;
    }
  }

  // List all rules
  listRules(): RuleSource[] {
    return Array.from(this.rules.values());
  }

  // Get current bundle version
  getBundleVersion(): string {
    return this.currentBundleVersion;
  }

  // Load a previously built bundle from disk
  async loadBundleByVersion(version: string): Promise<SignedYaraBundle | null> {
    const bundlePath = path.join(this.bundleDir, `${version}.json`);
    if (!fs.existsSync(bundlePath)) {
      return null;
    }
    const content = fs.readFileSync(bundlePath, 'utf-8');
    return JSON.parse(content) as SignedYaraBundle;
  }
}
