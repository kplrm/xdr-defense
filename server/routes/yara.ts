import { schema } from '@osd/config-schema';

import {
  buildSignedYaraBundle,
  getYaraForgeSyncMetadata,
  startYaraForgeCoreSync,
} from '../lib/yara_forge';
import {
  DEFAULT_MANAGER_POLICY_ID,
  acknowledgeYaraRolloutAgent,
  getLatestYaraRollout,
  listArtifacts,
  markYaraRolloutRetry,
  saveYaraRollout,
  YaraRolloutAction,
} from '../lib/store';

function toUtcDayIndex(timestampIso: string): string {
  const utcDay = timestampIso.slice(0, 10).replace(/-/g, '.');
  return `xdr-yara-rollout-status-${utcDay}`;
}

function toUtcInventoryDayIndex(timestampIso: string): string {
  const utcDay = timestampIso.slice(0, 10).replace(/-/g, '.');
  return `xdr-yara-rule-inventory-${utcDay}`;
}

function reportedAtToTimestamp(reportedAt: number): string {
  if (Number.isFinite(reportedAt) && reportedAt > 0) {
    return new Date(reportedAt * 1000).toISOString();
  }
  return new Date().toISOString();
}

export function registerYaraRoutes(router: any) {
  router.post(
    {
      path: '/api/xdr-defense/yara-forge/sync',
      validate: {
        body: schema.object({}, { unknowns: 'allow' }),
      },
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        const result = startYaraForgeCoreSync();
        return res.ok({
          body: {
            status: result.started ? 'started' : 'running',
            ...result,
          },
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to sync YARA Forge Core.',
            details: String(err?.message ?? err),
          },
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara-forge/status',
      validate: false,
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: getYaraForgeSyncMetadata() });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara/bundle',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const policyID = String(req.query?.policy_id ?? 'default');
      try {
        const bundle = await buildSignedYaraBundle(policyID);
        return res.ok({
          body: {
            ...bundle,
            manager_policy_id: policyID,
          },
        });
      } catch (err: any) {
        const details = String(err?.message ?? err);
        let forgeSync:
          | { started: boolean; startedAt?: string; pid?: number; message?: string }
          | undefined;

        if (details.includes('Bundle would be empty:') && details.includes('missing from disk')) {
          try {
            // Self-heal when YARA Forge files are missing after container rebuilds.
            forgeSync = startYaraForgeCoreSync();
          } catch {
            // Non-fatal: still return informative 503 details.
          }
        }

        return res.customError({
          statusCode: 503,
          body: {
            message: 'Failed to build signed YARA bundle.',
            // OSD serialises Boom errors as { statusCode, error, message, attributes }.
            // Extra top-level fields are stripped; attributes are preserved.
            attributes: {
              details,
              manager_policy_id: policyID,
              ...(forgeSync ? { forge_sync: forgeSync } : {}),
            },
          },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/{managerPolicyID}/reconcile',
      validate: {
        params: schema.object({
          managerPolicyID: schema.string({ minLength: 1 }),
        }),
        body: schema.object({
          action: schema.oneOf([
            schema.literal('sync'),
            schema.literal('activate'),
            schema.literal('deactivate'),
            schema.literal('delete'),
          ]),
          target_agent_ids: schema.arrayOf(schema.string({ minLength: 1 })),
          artifact_ids: schema.maybe(schema.arrayOf(schema.string({ minLength: 1 }))),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const managerPolicyID = req.params.managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
      const candidateArtifactIDs: string[] = req.body.artifact_ids ?? [];
      let artifactIDs = [...new Set(candidateArtifactIDs.filter((id) => id.length > 0))];

      if (artifactIDs.length === 0) {
        const enabledYaraArtifacts = (await listArtifacts(managerPolicyID)).filter(
          (artifact) => artifact.type === 'yara' && artifact.enabled
        );
        artifactIDs = enabledYaraArtifacts.map((artifact) => artifact.id);
      }

      const rollout = await saveYaraRollout({
        managerPolicyID,
        action: req.body.action as YaraRolloutAction,
        artifactIDs,
        targetAgentIDs: req.body.target_agent_ids ?? [],
      });

      return res.ok({ body: rollout });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara-rollouts/{managerPolicyID}/latest',
      validate: {
        params: schema.object({
          managerPolicyID: schema.string({ minLength: 1 }),
        }),
        query: schema.object({
          stale_after_seconds: schema.maybe(schema.number({ min: 60 })),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const managerPolicyID = req.params.managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
      const latest = await getLatestYaraRollout(managerPolicyID, req.query.stale_after_seconds);
      if (latest) {
        return res.ok({ body: latest });
      }

      return res.ok({
        body: {
          manager_policy_id: managerPolicyID,
          action: 'sync',
          artifact_ids: [],
          updated_at: new Date().toISOString(),
          target_agent_ids: [],
          pending_agent_ids: [],
          acked_agent_ids: [],
          failed_agent_ids: [],
          stale_pending_agent_ids: [],
          stale_after_seconds: req.query.stale_after_seconds ?? 900,
          agents: [],
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/{managerPolicyID}/retry',
      validate: {
        params: schema.object({
          managerPolicyID: schema.string({ minLength: 1 }),
        }),
        body: schema.object(
          {
            agent_ids: schema.maybe(schema.arrayOf(schema.string({ minLength: 1 }))),
          },
          {
            defaultValue: {},
          }
        ),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      // Retry requests commonly happen after container rebuilds where on-disk
      // forge rule files vanished. Kick off forge sync so retries have a path
      // to recovery without requiring a separate manual button click.
      let forgeSync: { started: boolean; startedAt?: string; pid?: number; message?: string } | undefined;
      try {
        forgeSync = startYaraForgeCoreSync();
      } catch {
        // Non-fatal: retry should still proceed even if sync start fails.
      }

      const rollout = await markYaraRolloutRetry({
        managerPolicyID: req.params.managerPolicyID,
        agentIDs: req.body.agent_ids,
      });

      if (!rollout) {
        return res.notFound({
          body: {
            message: `No YARA rollout found for policy ${req.params.managerPolicyID}.`,
          },
        });
      }

      return res.ok({
        body: {
          ...rollout,
          forge_sync: forgeSync,
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/ack',
      validate: {
        body: schema.object({
          manager_policy_id: schema.string({ minLength: 1 }),
          agent_id: schema.string({ minLength: 1 }),
          state: schema.oneOf([schema.literal('acked'), schema.literal('failed')]),
          hostname: schema.maybe(schema.string({ minLength: 1 })),
          failure_reason: schema.maybe(schema.string({ minLength: 1 })),
          action: schema.maybe(
            schema.oneOf([
              schema.literal('sync'),
              schema.literal('activate'),
              schema.literal('deactivate'),
              schema.literal('delete'),
            ])
          ),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const rollout = await acknowledgeYaraRolloutAgent({
        managerPolicyID: req.body.manager_policy_id,
        agentID: req.body.agent_id,
        hostname: req.body.hostname,
        state: req.body.state,
        failureReason: req.body.failure_reason,
        action: req.body.action,
      });

      if (!rollout) {
        return res.notFound({
          body: {
            message: `YARA rollout ${req.body.manager_policy_id} not found.`,
          },
        });
      }

      return res.ok({ body: rollout });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/status',
      validate: {
        body: schema.object({
          manager_policy_id: schema.string({ minLength: 1 }),
          agent_id: schema.string({ minLength: 1 }),
          state: schema.oneOf([
            schema.literal('acked'),
            schema.literal('partial'),
            schema.literal('failed'),
          ]),
          total_rules: schema.number({ min: 0 }),
          loaded_rules: schema.number({ min: 0 }),
          failed_rules: schema.arrayOf(
            schema.object({
              rule_id: schema.string({ minLength: 1 }),
              status: schema.string({ minLength: 1 }),
              error_message: schema.maybe(schema.string()),
              loaded_at: schema.maybe(schema.number()),
            })
          ),
          reported_at: schema.number({ min: 0 }),
          hostname: schema.maybe(schema.string({ minLength: 1 })),
        }),
      },
    },
    async (ctx: any, req: any, res: any) => {
      const timestamp = reportedAtToTimestamp(req.body.reported_at);
      const indexName = toUtcDayIndex(timestamp);

      const document = {
        '@timestamp': timestamp,
        event: {
          kind: 'state',
          category: 'configuration',
          type: 'info',
          module: 'xdr.yara',
        },
        agent: {
          id: req.body.agent_id,
        },
        ...(req.body.hostname ? { host: { hostname: req.body.hostname } } : {}),
        xdr: {
          manager_policy_id: req.body.manager_policy_id,
          agent_id: req.body.agent_id,
          state: req.body.state,
          total_rules: req.body.total_rules,
          loaded_rules: req.body.loaded_rules,
          failed_rules: req.body.failed_rules,
          failed_rules_count: req.body.failed_rules.length,
          reported_at: req.body.reported_at,
        },
      };

      try {
        const scopedClient = ctx.core.opensearch.client.asCurrentUser;
        await scopedClient.index({
          index: indexName,
          body: document,
          refresh: 'false',
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to persist YARA rollout status.',
            details: String(err?.message ?? err),
          },
        });
      }

      return res.ok({
        body: {
          accepted: true,
          manager_policy_id: req.body.manager_policy_id,
          agent_id: req.body.agent_id,
          indexed_index: indexName,
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rules/inventory',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          loaded_rule_count: schema.number({ min: 0 }),
          failed_rules: schema.arrayOf(
            schema.object({
              rule_id: schema.string({ minLength: 1 }),
              status: schema.string({ minLength: 1 }),
              error_message: schema.maybe(schema.string()),
              loaded_at: schema.maybe(schema.number()),
            })
          ),
          checked_at: schema.number({ min: 0 }),
        }),
      },
    },
    async (ctx: any, req: any, res: any) => {
      const timestamp = reportedAtToTimestamp(req.body.checked_at);
      const indexName = toUtcInventoryDayIndex(timestamp);

      const document = {
        '@timestamp': timestamp,
        event: {
          kind: 'state',
          category: 'configuration',
          type: 'info',
          module: 'xdr.yara',
        },
        agent: {
          id: req.body.agent_id,
        },
        xdr: {
          agent_id: req.body.agent_id,
          loaded_rule_count: req.body.loaded_rule_count,
          failed_rules: req.body.failed_rules,
          failed_rules_count: req.body.failed_rules.length,
          checked_at: req.body.checked_at,
        },
      };

      try {
        const scopedClient = ctx.core.opensearch.client.asCurrentUser;
        await scopedClient.index({
          index: indexName,
          body: document,
          refresh: 'false',
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to persist YARA rule inventory report.',
            details: String(err?.message ?? err),
          },
        });
      }

      return res.ok({
        body: {
          accepted: true,
          agent_id: req.body.agent_id,
          indexed_index: indexName,
        },
      });
    }
  );
}