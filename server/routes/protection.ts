declare const require: any;

import {
  addCustomProtectionRule,
  buildSignedProtectionBundle,
  deleteProtectionRule,
  getProtectionSigningReadiness,
  listProtectionRules,
  syncProtectionOpenSource,
  type ProtectionSyncResult,
  type ProtectionSyncStep,
  updateProtectionRule,
  type ProtectionNamespace
} from '../lib/protection_registry';
import {
  ingestProtectionRolloutStatusReport,
  listProtectionRolloutStatus
} from '../lib/protection_rollout_status';

const { schema } = require('@osd/config-schema');

type SyncJobStatus = 'running' | 'completed' | 'failed';

interface ProtectionSyncJobRecord {
  id: string;
  namespace: ProtectionNamespace;
  status: SyncJobStatus;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  steps: ProtectionSyncStep[];
  result?: ProtectionSyncResult;
  error?: string;
}

const protectionSyncJobsByNamespace = new Map<ProtectionNamespace, ProtectionSyncJobRecord>();
const protectionSyncJobsById = new Map<string, ProtectionSyncJobRecord>();

function nowIso(): string {
  return new Date().toISOString();
}

function createSyncJobId(namespace: ProtectionNamespace): string {
  return `${namespace}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function serializeSyncJob(job: ProtectionSyncJobRecord): Record<string, unknown> {
  return {
    job_id: job.id,
    namespace: job.namespace,
    status: job.status,
    created_at: job.createdAt,
    updated_at: job.updatedAt,
    completed_at: job.completedAt,
    steps: job.steps,
    result: job.result,
    error: job.error
  };
}

function scopedOsClient(ctx: any): any | null {
  if (typeof ctx?.core?.opensearch?.client?.asInternalUser?.search === 'function') {
    return ctx.core.opensearch.client.asInternalUser;
  }
  if (typeof ctx?.opensearch?.client?.asInternalUser?.search === 'function') {
    return ctx.opensearch.client.asInternalUser;
  }
  if (typeof ctx?.core?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.core.opensearch.client.asCurrentUser;
  }
  if (typeof ctx?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.opensearch.client.asCurrentUser;
  }
  return null;
}

function title(namespace: ProtectionNamespace): string {
  return namespace === 'memory' ? 'Memory protection' : 'Ransomware protection';
}

function registerProtectionRoutes(router: any, namespace: ProtectionNamespace): void {
  const basePath = `/api/xdr-defense/${namespace}`;

  router.get(
    {
      path: `${basePath}/rules`,
      validate: {
        query: schema.object({
          q: schema.maybe(schema.string({ maxLength: 256 })),
          page: schema.maybe(schema.number({ min: 1, max: 100000 })),
          pageSize: schema.maybe(schema.number({ min: 1, max: 500 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const result = await listProtectionRules(client, namespace, {
          q: req.query?.q,
          page: req.query?.page,
          pageSize: req.query?.pageSize
        });

        return res.ok({
          body: {
            rules: result.rules,
            page: result.page,
            pageSize: result.pageSize,
            total: result.total,
            totalPages: Math.max(1, Math.ceil(result.total / result.pageSize))
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to list ${title(namespace)} rules.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: `${basePath}/rules`,
      validate: {
        body: schema.object({
          name: schema.string({ minLength: 1, maxLength: 160 }),
          content: schema.string({ minLength: 1, maxLength: 200000 }),
          enabled: schema.maybe(schema.boolean()),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const created = await addCustomProtectionRule(client, namespace, req.body ?? {});
        if (created.validation.status === 'invalid') {
          return res.customError({
            statusCode: 400,
            body: {
              message: `${title(namespace)} rule validation failed.`,
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
            message: `Failed to create ${title(namespace)} rule.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.put(
    {
      path: `${basePath}/rules/{id}`,
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
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const result = await updateProtectionRule(client, namespace, req.params.id, req.body ?? {});
        if (!result.updated) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({ statusCode: code, body: { message: result.error ?? 'Update failed.' } });
        }

        return res.ok({ body: result.updated });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to update ${title(namespace)} rule.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.delete(
    {
      path: `${basePath}/rules/{id}`,
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const result = await deleteProtectionRule(client, namespace, req.params.id);
        if (!result.deleted) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({ statusCode: code, body: { message: result.error ?? 'Delete failed.' } });
        }

        return res.ok({ body: { deleted: true, id: req.params.id } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to delete ${title(namespace)} rule.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: `${basePath}/bundle`,
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const readiness = getProtectionSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: `Signed ${title(namespace)} bundle generation unavailable.`,
              details: readiness.reason
            }
          });
        }

        const policyId = String(req.query?.policy_id ?? 'global-default');
        const result = await buildSignedProtectionBundle(client, namespace, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: `Failed to build signed ${title(namespace)} bundle.`,
              details: result.error ?? 'Unknown signing failure.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to fetch ${title(namespace)} bundle.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: `${basePath}/bundle/build`,
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const readiness = getProtectionSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: `Signed ${title(namespace)} bundle generation unavailable.`,
              details: readiness.reason
            }
          });
        }

        const policyId = String(req.body?.policy_id ?? 'global-default');
        const result = await buildSignedProtectionBundle(client, namespace, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: `Failed to build signed ${title(namespace)} bundle.`,
              details: result.error ?? 'Unknown signing failure.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to build ${title(namespace)} bundle.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: `${basePath}/open-source/sync/jobs`,
      validate: false
    },
    async (ctx: any, _req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const existing = protectionSyncJobsByNamespace.get(namespace);
        if (existing && existing.status === 'running') {
          return res.ok({
            body: {
              started: false,
              already_running: true,
              job: serializeSyncJob(existing)
            }
          });
        }

        const createdAt = nowIso();
        const job: ProtectionSyncJobRecord = {
          id: createSyncJobId(namespace),
          namespace,
          status: 'running',
          createdAt,
          updatedAt: createdAt,
          steps: [
            {
              stage: 'job_created',
              message: `${title(namespace)} sync job created and queued.`,
              at: createdAt
            }
          ]
        };

        protectionSyncJobsByNamespace.set(namespace, job);
        protectionSyncJobsById.set(job.id, job);

        (async () => {
          try {
            const result = await syncProtectionOpenSource(client, namespace, (step) => {
              job.steps.push(step);
              job.updatedAt = step.at;
            });
            job.result = result;
            job.status = 'completed';
            job.completedAt = nowIso();
            job.updatedAt = job.completedAt;
          } catch (err: any) {
            const failedAt = nowIso();
            job.status = 'failed';
            job.error = String(err?.message ?? err);
            job.completedAt = failedAt;
            job.updatedAt = failedAt;
            job.steps.push({
              stage: 'failed',
              message: `Sync failed: ${job.error}`,
              at: failedAt
            });
          }
        })();

        return res.ok({
          body: {
            started: true,
            job: serializeSyncJob(job)
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to start open-source ${title(namespace)} sync job.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: `${basePath}/open-source/sync/jobs/{job_id}`,
      validate: {
        params: schema.object({
          job_id: schema.string({ minLength: 1, maxLength: 256 })
        })
      }
    },
    async (_ctx: any, req: any, res: any) => {
      const jobId = String(req.params?.job_id ?? '');
      const job = protectionSyncJobsById.get(jobId);

      if (!job || job.namespace !== namespace) {
        return res.customError({ statusCode: 404, body: { message: 'Sync job not found.' } });
      }

      return res.ok({ body: serializeSyncJob(job) });
    }
  );

  router.post(
    {
      path: `${basePath}/open-source/sync`,
      validate: false
    },
    async (ctx: any, _req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const syncResult = await syncProtectionOpenSource(client, namespace);
        return res.ok({ body: syncResult });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to sync open-source ${title(namespace)} rules.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: `${basePath}/rollout`,
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const policyId = String(req.body?.policy_id ?? 'global-default');
        const result = await buildSignedProtectionBundle(client, namespace, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              started: false,
              message: `Unable to prepare ${title(namespace)} rollout bundle.`,
              details: result.error ?? 'Unknown signing failure.'
            }
          });
        }

        return res.ok({
          body: {
            started: true,
            success: true,
            message: `${title(namespace)} rollout trigger accepted for all agents.`,
            policy_id: policyId,
            bundle_version: result.bundle.bundle_version,
            generated_at: result.bundle.generated_at,
            rule_count: result.bundle.rules.length
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            started: false,
            message: `Failed to trigger ${title(namespace)} rollout.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: `${basePath}/rollouts/status`,
      validate: {
        query: schema.object({
          page: schema.maybe(schema.number({ min: 1, max: 100000 })),
          pageSize: schema.maybe(schema.number({ min: 1, max: 500 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const status = await listProtectionRolloutStatus(client, namespace, {
          page: req.query?.page,
          pageSize: req.query?.pageSize
        });
        return res.ok({ body: status });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to load ${title(namespace)} rollout status.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: `${basePath}/rollouts/status/report`,
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1, maxLength: 256 }),
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
          state: schema.string({ minLength: 1, maxLength: 64 }),
          bundle_version: schema.maybe(schema.number({ min: 0 })),
          total_rules: schema.maybe(schema.number({ min: 0 })),
          loaded_rules: schema.maybe(schema.number({ min: 0 })),
          reported_at: schema.maybe(schema.oneOf([schema.number({ min: 0 }), schema.string({ minLength: 1, maxLength: 128 })])),
          error: schema.maybe(schema.string({ minLength: 1, maxLength: 4096 })),
          agent_hostname: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const ingestion = await ingestProtectionRolloutStatusReport(client, namespace, req.body ?? {});
        return res.ok({ body: ingestion });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: `Failed to ingest ${title(namespace)} rollout status report.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: `${basePath}/rollouts/retry`,
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        }, { defaultValue: {} })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const policyId = String(req.body?.policy_id ?? 'global-default');
        const result = await buildSignedProtectionBundle(client, namespace, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 409,
            body: {
              success: false,
              message: `No ${title(namespace)} bundle is available to retry.`,
              details: result.error ?? 'Build a bundle first.'
            }
          });
        }

        return res.ok({
          body: {
            success: true,
            message: `${title(namespace)} rollout retry queued for all agents.`,
            policy_id: policyId,
            bundle_version: result.bundle.bundle_version,
            generated_at: result.bundle.generated_at,
            rule_count: result.bundle.rules.length
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            success: false,
            message: `Failed to retry ${title(namespace)} rollout.`,
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );
}

export function registerMemoryRoutes(router: any): void {
  registerProtectionRoutes(router, 'memory');
}

export function registerRansomwareRoutes(router: any): void {
  registerProtectionRoutes(router, 'ransomware');
}
