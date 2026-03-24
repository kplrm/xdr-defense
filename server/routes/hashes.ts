declare const require: any;

import {
  addCustomHashRule,
  buildSignedHashBundle,
  deleteHashRule,
  getExistingMalwareBazaarHashRuleState,
  getHashSigningReadiness,
  listHashRules,
  updateHashRule,
  upsertMalwareBazaarHashRule
} from '../lib/hashes_store';
import { loadMalwareBazaarSources, syncHashSourcesWithWorkerPool } from '../lib/hashes_open_source';

const { schema } = require('@osd/config-schema');

export function registerHashRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr-defense/hashes/rules',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        const rules = listHashRules();
        return res.ok({ body: { rules } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to list hash rules.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/rules',
      validate: {
        body: schema.object({
          name: schema.string({ minLength: 1, maxLength: 160 }),
          content: schema.string({ minLength: 1, maxLength: 200000 }),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 }))
        })
      }
    },
    async (_ctx: any, req: any, res: any) => {
      try {
        const created = addCustomHashRule(req.body ?? {});
        const statusCode = created.validation.status === 'valid' ? 200 : 400;
        if (statusCode === 400) {
          return res.customError({
            statusCode,
            body: {
              message: 'Hash rule validation failed.',
              rule: created,
              validation: created.validation
            }
          });
        }
        return res.ok({ body: created });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to create hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/hashes/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }),
        body: schema.object({
          enabled: schema.maybe(schema.boolean()),
          content: schema.maybe(schema.string({ minLength: 1, maxLength: 200000 })),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 })),
          name: schema.maybe(schema.string({ minLength: 1, maxLength: 160 }))
        })
      }
    },
    async (_ctx: any, req: any, res: any) => {
      try {
        const result = updateHashRule(req.params.id, req.body ?? {});
        if (!result.updated) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({
            statusCode: code,
            body: {
              message: result.error ?? 'Failed to update hash rule.'
            }
          });
        }
        return res.ok({ body: result.updated });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to update hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.delete(
    {
      path: '/api/xdr-defense/hashes/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) })
      }
    },
    async (_ctx: any, req: any, res: any) => {
      try {
        const result = deleteHashRule(req.params.id);
        if (!result.deleted) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({
            statusCode: code,
            body: {
              message: result.error ?? 'Failed to delete hash rule.'
            }
          });
        }
        return res.ok({ body: { deleted: true, id: req.params.id } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to delete hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/bundle',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const policyId = String(req.query?.policy_id ?? 'global-default');
        const readiness = getHashSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed hash bundle generation unavailable.',
              details: readiness.reason
            }
          });
        }

        const result = buildSignedHashBundle(policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed hash bundle generation unavailable.',
              details: result.error ?? 'Failed to sign bundle.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build hash bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/bundle/build',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const policyId = String(req.body?.policy_id ?? 'global-default');
        const readiness = getHashSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Hash bundle signing unavailable.',
              details: readiness.reason
            }
          });
        }

        const result = buildSignedHashBundle(policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Hash bundle generation failed.',
              details: result.error ?? 'Unknown error.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build hash bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/open-source/sync',
      validate: false
    },
    async (_ctx: any, _req: any, res: any) => {
      try {
        const sources = await loadMalwareBazaarSources();
        const syncResult = await syncHashSourcesWithWorkerPool(sources);

        let imported = 0;
        let unchanged = 0;
        const importErrors: string[] = [];

        const sourceById = new Map<string, (typeof sources)[number]>();
        for (const source of sources) {
          sourceById.set(source.id, source);
        }

        for (const item of syncResult.items) {
          if (!item.ok || !item.content) {
            importErrors.push(`${item.id}: ${item.error ?? 'load failed'}`);
            continue;
          }

          const source = sourceById.get(item.id);
          const existingState = getExistingMalwareBazaarHashRuleState(item.id);
          const upserted = upsertMalwareBazaarHashRule({
            id: item.id,
            name: item.name,
            content: item.content,
            severity: source?.severity ?? 'medium',
            tags: source?.tags ?? ['malwarebazaar', 'synced'],
            enabled: existingState ? existingState.enabled : true
          });

          if (!upserted.changed) {
            unchanged += 1;
          } else {
            imported += 1;
          }
        }

        return res.ok({
          body: {
            message: 'MalwareBazaar hash sync completed.',
            parallel_workers: syncResult.worker_count,
            attempted: syncResult.attempted,
            loaded: syncResult.succeeded,
            load_failures: syncResult.failed,
            imported,
            unchanged,
            errors: importErrors.sort((a, b) => a.localeCompare(b))
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to sync open-source hashes.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );
}