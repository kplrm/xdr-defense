// xdr-defense signed YARA artifact routes

import { SignedBundleStore, RuleSource, SignedYaraBundle } from '../lib/signed-bundle-store';
import * as path from 'path';
import * as fs from 'fs';

// Global store instance (in production, use DI)
let bundleStore: SignedBundleStore;

export function initSignedBundleStore(rulesDir: string, bundleDir: string, privateKeyPath: string) {
  bundleStore = new SignedBundleStore(rulesDir, bundleDir, privateKeyPath);
}

export function registerSignedArtifactRoutes(router: any) {
  // GET /api/xdr-defense/signed-artifacts/yara-rules
  // List all YARA rules with metadata
  router.get(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-rules',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        const rules = bundleStore.listRules();
        return res.ok({ body: { rules } });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );

  // POST /api/xdr-defense/signed-artifacts/yara-rules
  // Create or update a YARA rule
  router.post(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-rules',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const rule = req.body as RuleSource;
        
        // Validate required fields
        if (!rule.id || !rule.name || !rule.file_path || !rule.severity) {
          return res.badRequest({ body: { error: 'Missing required fields: id, name, file_path, severity' } });
        }

        // Write rule file to disk if provided
        if (req.body.content) {
          const rulePath = path.join(process.env.XDR_RULES_DIR || '/etc/xdr-agent/rules/malware/yara', rule.file_path);
          fs.mkdirSync(path.dirname(rulePath), { recursive: true });
          fs.writeFileSync(rulePath, req.body.content);

          // Update checksum
          const crypto = await import('crypto');
          const hash = crypto.createHash('sha256');
          hash.update(req.body.content);
          rule.checksum_sha256 = hash.digest('hex');
        }

        bundleStore.addOrUpdateRule(rule);
        return res.ok({ body: { message: 'Rule added/updated', rule } });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );

  // DELETE /api/xdr-defense/signed-artifacts/yara-rules/:ruleId
  // Delete a custom YARA rule
  router.delete(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-rules/:ruleId',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const ruleId = req.params.ruleId;
        const deleted = bundleStore.deleteRule(ruleId);
        if (!deleted) {
          return res.notFound({ body: { error: `Rule ${ruleId} not found` } });
        }
        return res.ok({ body: { message: 'Rule deleted', ruleId } });
      } catch (err: any) {
        return res.badRequest({ body: { error: err.message } });
      }
    }
  );

  // PUT /api/xdr-defense/signed-artifacts/yara-rules/:ruleId/toggle
  // Enable or disable a rule
  router.put(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-rules/:ruleId/toggle',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const ruleId = req.params.ruleId;
        const enabled = req.body?.enabled ?? true;
        bundleStore.toggleRule(ruleId, enabled);
        return res.ok({ body: { message: `Rule ${enabled ? 'enabled' : 'disabled'}`, ruleId } });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );

  // POST /api/xdr-defense/signed-artifacts/yara-rules/:ruleId/validate
  // Validate a single rule (compile test)
  router.post(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-rules/:ruleId/validate',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const ruleId = req.params.ruleId;
        const validation = await bundleStore.validateRule(ruleId);
        if (!validation.valid) {
          return res.badRequest({ body: { valid: false, error: validation.error } });
        }
        return res.ok({ body: { valid: true, ruleId } });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );

  // POST /api/xdr-defense/signed-artifacts/yara-bundle/build
  // Build and sign a new YARA bundle
  router.post(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-bundle/build',
      validate: false
    },
    async (_ctx: unknown, _req: any, res: any) => {
      try {
        const bundle = await bundleStore.buildAndSignBundle();
        return res.ok({ body: { bundle, version: bundle.manifest.version } });
      } catch (err: any) {
        return res.badRequest({ body: { error: err.message } });
      }
    }
  );

  // GET /api/xdr-defense/signed-artifacts/yara-bundle
  // Get latest signed YARA bundle for agents to consume
  router.get(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-bundle',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        const version = bundleStore.getBundleVersion();
        if (!version) {
          return res.notFound({ body: { error: 'No bundle has been built yet' } });
        }

        const bundle = await bundleStore.loadBundleByVersion(version);
        if (!bundle) {
          return res.notFound({ body: { error: `Bundle ${version} not found` } });
        }

        return res.ok({
          body: {
            bundle,
            version,
            download_url: `/api/xdr-defense/signed-artifacts/yara-bundle/files`
          }
        });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );

  // GET /api/xdr-defense/signed-artifacts/yara-bundle/files
  // Download individual rule files from the bundle
  router.get(
    {
      path: '/api/xdr-defense/signed-artifacts/yara-bundle/files',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const ruleId = req.query.id;
        if (!ruleId) {
          return res.badRequest({ body: { error: 'Query parameter "id" required' } });
        }

        const rules = bundleStore.listRules();
        const rule = rules.find(r => r.id === ruleId);
        if (!rule) {
          return res.notFound({ body: { error: `Rule ${ruleId} not found` } });
        }

        const rulesDir = process.env.XDR_RULES_DIR || '/etc/xdr-agent/rules/malware/yara';
        const rulePath = path.join(rulesDir, rule.file_path);
        if (!fs.existsSync(rulePath)) {
          return res.notFound({ body: { error: `Rule file not found: ${rulePath}` } });
        }

        const content = fs.readFileSync(rulePath);
        res.set('Content-Type', 'text/plain');
        res.set('ETag', `"${rule.checksum_sha256}"`);
        return res.ok({ body: content });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );

  // POST /api/xdr-defense/signed-artifacts/verify-bundle
  // Verify bundle signature (for testing/audit)
  router.post(
    {
      path: '/api/xdr-defense/signed-artifacts/verify-bundle',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const bundle: SignedYaraBundle = req.body as SignedYaraBundle;
        const valid = SignedBundleStore.verifyBundleSignature(bundle);
        return res.ok({ body: { valid } });
      } catch (err: any) {
        return res.internalError({ body: { error: err.message } });
      }
    }
  );
}
