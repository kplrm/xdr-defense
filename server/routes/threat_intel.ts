import { schema } from '@osd/config-schema';

import {
  listThreatFeeds,
  markThreatFeedSynced,
  upsertArtifact,
  upsertThreatFeed,
} from '../lib/store';

export function registerThreatIntelRoutes(router: any) {
  router.get(
    {
      path: '/api/xdr-defense/threat-intel/feeds',
      validate: false,
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      return res.ok({ body: { feeds: await listThreatFeeds() } });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/threat-intel/feeds',
      validate: {
        body: schema.object({
          id: schema.string({ minLength: 1 }),
          name: schema.string({ minLength: 1 }),
          type: schema.oneOf([
            schema.literal('hashes'),
            schema.literal('domain'),
            schema.literal('ip'),
            schema.literal('url'),
          ]),
          url: schema.string({ minLength: 1 }),
          enabled: schema.boolean({ defaultValue: true }),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const body = req.body;
      const feed = await upsertThreatFeed({
        id: body.id,
        name: body.name,
        type: body.type,
        url: body.url,
        enabled: body.enabled,
      });
      return res.ok({ body: feed });
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/threat-intel/sync',
      validate: {
        body: schema.object({
          feed_id: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_ctx: unknown, req: any, res: any) => {
      const feed = await markThreatFeedSynced(req.body.feed_id);
      const artifact = await upsertArtifact({
        id: `ti-${feed.id}`,
        type: 'threatintel',
        version: feed.lastSyncAt ?? new Date().toISOString(),
        checksum: 'sha256:pending',
        sourceUrl: feed.url,
        description: `Threat intel package generated from feed ${feed.name}`,
      });

      return res.ok({
        body: {
          status: 'queued',
          feed,
          artifact,
          queued_at: new Date().toISOString(),
        },
      });
    }
  );
}
