import { schema } from '@osd/config-schema';

import { listCorrelationRuleAssets } from '../lib/assets';
import { latestArtifactManifest, listArtifacts, upsertArtifact } from '../lib/store';

export function registerArtifactRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/artifacts',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: { artifacts: await listArtifacts() } });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/artifacts',
      validate: {
        body: schema.object({
          id: schema.string({ minLength: 1 }),
          type: schema.oneOf([
            schema.literal('yara'),
            schema.literal('behavioral'),
            schema.literal('hashes'),
            schema.literal('threatintel'),
          ]),
          version: schema.string({ minLength: 1 }),
          checksum: schema.string({ minLength: 1 }),
          sourceUrl: schema.maybe(schema.string()),
          description: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const body = req.body;
      const artifact = await upsertArtifact({
        id: body.id,
        type: body.type,
        version: body.version,
        checksum: body.checksum,
        sourceUrl: body.sourceUrl,
        description: body.description,
      });
      return res.ok({ body: artifact });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/artifacts/manifest/latest',
      validate: false,
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: await latestArtifactManifest() });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/correlation-rules',
      validate: false,
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: { rules: listCorrelationRuleAssets() } });
    }
  );
}
