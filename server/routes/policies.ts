import { schema } from '@osd/config-schema';

import {
  acknowledgePolicyRolloutAgent,
  DEFAULT_MANAGER_POLICY_ID,
  getLatestPolicyRollout,
  getPolicyOverlay,
  listPolicyOverlays,
  markPolicyRolloutRetry,
  savePolicyOverlay,
  savePolicyRollout,
} from '../lib/store';

function toRolloutResponse(rollout: {
  policy_id: string;
  posture_version: number;
  target_agent_ids: string[];
  acked_agent_ids: string[];
  pending_agent_ids: string[];
}) {
  return {
    policy_id: rollout.policy_id,
    posture_version: rollout.posture_version,
    target_agents: rollout.target_agent_ids.length,
    acked_agents: rollout.acked_agent_ids.length,
    pending_agents: rollout.pending_agent_ids,
  };
}

export function registerPolicyRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/policy-overlays',
      validate: false,
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      const overlays = await listPolicyOverlays();
      return res.ok({
        body: {
          overlays: overlays.map((entry) => ({
            manager_policy_id: entry.managerPolicyID,
            ...entry.overlay,
          })),
        },
      });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/policy-overlays/{managerPolicyID}',
      validate: {
        params: schema.object({
          managerPolicyID: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const overlay = await getPolicyOverlay(req.params.managerPolicyID);
      return res.ok({
        body: {
          manager_policy_id: req.params.managerPolicyID,
          ...overlay,
        },
      });
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/policy-overlays/{managerPolicyID}',
      validate: {
        params: schema.object({
          managerPolicyID: schema.string({ minLength: 1 }),
        }),
        body: schema.object({
          mode: schema.oneOf([schema.literal('detect'), schema.literal('prevent')]),
          capabilities: schema.recordOf(schema.string(), schema.boolean()),
          target_agent_ids: schema.maybe(schema.arrayOf(schema.string({ minLength: 1 }))),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const overlay = await savePolicyOverlay(req.params.managerPolicyID, {
        mode: req.body.mode,
        capabilities: req.body.capabilities,
      });
      const rollout = await savePolicyRollout(
        req.params.managerPolicyID,
        overlay.version,
        req.body.target_agent_ids ?? []
      );

      return res.ok({
        body: {
          manager_policy_id: req.params.managerPolicyID,
          ...overlay,
          rollout: toRolloutResponse(rollout),
        },
      });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/policy-rollouts/{managerPolicyID}/latest',
      validate: {
        params: schema.object({
          managerPolicyID: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const latest = await getLatestPolicyRollout(req.params.managerPolicyID);
      if (latest) {
        return res.ok({ body: latest });
      }

      const overlay = await getPolicyOverlay(req.params.managerPolicyID);
      return res.ok({
        body: {
          policy_id: req.params.managerPolicyID,
          posture_version: overlay.version,
          updated_at: overlay.updatedAt,
          target_agent_ids: [],
          acked_agent_ids: [],
          pending_agent_ids: [],
          acked_agents: [],
          retry_requested_at: {},
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/policy-rollouts/{managerPolicyID}/retry',
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
      const rollout = await markPolicyRolloutRetry({
        policyID: req.params.managerPolicyID,
        agentIDs: req.body.agent_ids,
      });

      if (!rollout) {
        const overlay = await getPolicyOverlay(req.params.managerPolicyID);
        return res.ok({
          body: {
            policy_id: req.params.managerPolicyID,
            posture_version: overlay.version,
            updated_at: overlay.updatedAt,
            target_agent_ids: [],
            acked_agent_ids: [],
            pending_agent_ids: [],
            acked_agents: [],
            retry_requested_at: {},
          },
        });
      }

      return res.ok({ body: rollout });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/policy-rollouts/ack',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          policy_id: schema.string({ minLength: 1 }),
          posture_version: schema.number({ min: 1 }),
          hostname: schema.maybe(schema.string({ minLength: 1 })),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const rollout = await acknowledgePolicyRolloutAgent({
        policyID: req.body.policy_id,
        postureVersion: req.body.posture_version,
        agentID: req.body.agent_id,
        hostname: req.body.hostname,
      });
      return res.ok({ body: rollout });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/policy',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const policyID = req.query.policy_id || DEFAULT_MANAGER_POLICY_ID;
      return res.ok({ body: await getPolicyOverlay(policyID) });
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/policy',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string()),
          mode: schema.oneOf([schema.literal('detect'), schema.literal('prevent')]),
          capabilities: schema.recordOf(schema.string(), schema.boolean()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const body = req.body;
      const policy = await savePolicyOverlay(body.policy_id || DEFAULT_MANAGER_POLICY_ID, {
        mode: body.mode,
        capabilities: body.capabilities,
      });
      return res.ok({ body: policy });
    }
  );
}
