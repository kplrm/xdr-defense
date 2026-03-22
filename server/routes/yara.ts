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
      try {
        const policyID = String(req.query?.policy_id ?? 'default');
        const bundle = await buildSignedYaraBundle(policyID);
        return res.ok({ body: bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 503,
          body: {
            message: 'Failed to build signed YARA bundle.',
            details: String(err?.message ?? err),
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
          rollout_version: 0,
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

      return res.ok({ body: rollout });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/ack',
      validate: {
        body: schema.object({
          manager_policy_id: schema.string({ minLength: 1 }),
          rollout_version: schema.number({ min: 1 }),
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
        rolloutVersion: req.body.rollout_version,
        agentID: req.body.agent_id,
        hostname: req.body.hostname,
        state: req.body.state,
        failureReason: req.body.failure_reason,
        action: req.body.action,
      });

      if (!rollout) {
        return res.notFound({
          body: {
            message: `YARA rollout ${req.body.manager_policy_id}:${req.body.rollout_version} not found.`,
          },
        });
      }

      return res.ok({ body: rollout });
    }
  );
}