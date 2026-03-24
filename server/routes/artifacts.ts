import { listArtifacts, upsertArtifact } from '../lib/store';

export function registerArtifactRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/artifacts',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: { artifacts: listArtifacts() } });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/artifacts',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      const body = req.body ?? {};
      const artifact = upsertArtifact({
        id: body.id,
        type: body.type,
        version: body.version,
        checksum: body.checksum,
        updatedAt: new Date().toISOString()
      });
      return res.ok({ body: artifact });
    }
  );
}
