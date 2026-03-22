import { schema } from '@osd/config-schema';

import { getPolicy, savePolicy } from '../lib/store';

export function registerPolicyRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/policy',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: await getPolicy() });
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/policy',
      validate: {
        body: schema.object({
          mode: schema.oneOf([schema.literal('detect'), schema.literal('prevent')]),
          capabilities: schema.recordOf(schema.string(), schema.boolean()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const body = req.body;
      const policy = await savePolicy({
        mode: body.mode,
        capabilities: body.capabilities,
      });
      return res.ok({ body: policy });
    }
  );
}
