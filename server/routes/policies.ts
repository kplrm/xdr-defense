declare const require: any;

import { getPolicy, savePolicy } from '../lib/store';

const { schema } = require('@osd/config-schema');

export function registerPolicyRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/policy',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: getPolicy() });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/policy-overlays/{policyId}',
      options: {
        authRequired: false
      },
      validate: {
        params: schema.object({
          policyId: schema.string({ minLength: 1, maxLength: 256 })
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      const policy = getPolicy();
      return res.ok({
        body: {
          manager_policy_id: String(req.params?.policyId ?? 'global-default'),
          mode: policy.mode,
          capabilities: policy.capabilities,
          updatedAt: policy.updatedAt,
          version: policy.version
        }
      });
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/policy',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      const body = req.body ?? {};
      const policy = savePolicy({
        mode: body.mode === 'prevent' ? 'prevent' : 'detect',
        capabilities: body.capabilities ?? {}
      });
      return res.ok({ body: policy });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/policy-rollouts/ack',
      options: {
        authRequired: false
      },
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1, maxLength: 256 }),
          policy_id: schema.string({ minLength: 1, maxLength: 256 }),
          posture_version: schema.number({ min: 0 }),
          hostname: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      return res.ok({
        body: {
          acknowledged: true,
          agent_id: req.body.agent_id,
          policy_id: req.body.policy_id,
          posture_version: req.body.posture_version,
          hostname: req.body.hostname,
          received_at: new Date().toISOString()
        }
      });
    }
  );
}
