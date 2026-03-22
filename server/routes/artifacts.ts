import { schema } from '@osd/config-schema';

import { listCorrelationRuleAssets } from '../lib/assets';
import {
  deleteArtifact,
  latestArtifactManifest,
  listArtifacts,
  setArtifactEnabled,
  upsertArtifact,
} from '../lib/store';

export function registerArtifactRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/artifacts',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      return res.ok({ body: { artifacts: await listArtifacts(req.query.policy_id) } });
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
          enabled: schema.maybe(schema.boolean()),
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
        enabled: body.enabled,
        sourceUrl: body.sourceUrl,
        description: body.description,
      });
      return res.ok({ body: artifact });
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/artifacts/{artifact_id}/state',
      validate: {
        params: schema.object({
          artifact_id: schema.string({ minLength: 1 }),
        }),
        query: schema.object({
          policy_id: schema.maybe(schema.string()),
        }),
        body: schema.object({
          enabled: schema.boolean(),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const artifact = await setArtifactEnabled(
        req.params.artifact_id,
        req.body.enabled,
        req.query.policy_id
      );
      return res.ok({ body: artifact });
    }
  );

  router.delete(
    {
      path: '/api/xdr-defense/artifacts/{artifact_id}',
      validate: {
        params: schema.object({
          artifact_id: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const deleted = await deleteArtifact(req.params.artifact_id);
      if (!deleted) {
        return res.notFound({
          body: {
            message: `Artifact not found: ${req.params.artifact_id}`,
          },
        });
      }
      return res.ok({ body: { deleted: true, id: req.params.artifact_id } });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/artifacts/manifest/latest',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string()),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      return res.ok({ body: await latestArtifactManifest(req.query.policy_id) });
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
