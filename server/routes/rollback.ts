import { schema } from '@osd/config-schema';

import { getEffectivePolicy, listArtifacts, listThreatFeeds } from '../lib/store';

export function registerRollbackRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/summary',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const [policy, artifacts, feeds] = await Promise.all([
        getEffectivePolicy(req.query.policy_id),
        listArtifacts(req.query.policy_id),
        listThreatFeeds(),
      ]);
      return res.ok({
        body: {
          policy,
          artifact_count: artifacts.length,
          feed_count: feeds.length,
          prevention_enabled: Boolean(policy.capabilities['prevention.enabled']),
          rollback_enabled: Boolean(policy.capabilities['rollback.enabled']),
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/rollback/confirm',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          incident_id: schema.string({ minLength: 1 }),
          reason: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      return res.ok({
        body: {
          status: 'confirmed',
          agent_id: req.body.agent_id,
          incident_id: req.body.incident_id,
          reason: req.body.reason,
          confirmed_at: new Date().toISOString()
        }
      });
    }
  );
}
