import { getPolicy, savePolicy } from '../lib/store';

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
}
