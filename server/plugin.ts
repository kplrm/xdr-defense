import { registerArtifactRoutes } from './routes/artifacts';
import { registerPolicyRoutes } from './routes/policies';
import { registerRollbackRoutes } from './routes/rollback';
import { registerThreatIntelRoutes } from './routes/threat_intel';
import { installManagedAssets } from './lib/assets';
import {
  ARTIFACT_SAVED_OBJECT_TYPE,
  bindRepository,
  FEED_SAVED_OBJECT_TYPE,
  POLICY_SAVED_OBJECT_TYPE,
} from './lib/store';
import {
  CoreSetup,
  CoreStart,
  Plugin,
  PluginInitializerContext,
} from '../../../src/core/server';

export class XdrDefenseServerPlugin implements Plugin<Record<string, never>, Record<string, never>> {
  constructor(private readonly initializerContext: PluginInitializerContext) {}

  public setup(core: CoreSetup): Record<string, never> {
    this.initializerContext.logger.get().debug('xdr_defense: setup');

    core.savedObjects.registerType({
      name: POLICY_SAVED_OBJECT_TYPE,
      hidden: true,
      namespaceType: 'agnostic',
      mappings: {
        properties: {
          mode: { type: 'keyword' },
          capabilitiesJSON: { type: 'text', index: false },
          updatedAt: { type: 'date' },
          version: { type: 'integer' },
        },
      },
    });

    core.savedObjects.registerType({
      name: ARTIFACT_SAVED_OBJECT_TYPE,
      hidden: true,
      namespaceType: 'agnostic',
      mappings: {
        properties: {
          id: { type: 'keyword' },
          type: { type: 'keyword' },
          version: { type: 'keyword' },
          checksum: { type: 'keyword' },
          updatedAt: { type: 'date' },
          sourceUrl: { type: 'keyword' },
          description: { type: 'text' },
        },
      },
    });

    core.savedObjects.registerType({
      name: FEED_SAVED_OBJECT_TYPE,
      hidden: true,
      namespaceType: 'agnostic',
      mappings: {
        properties: {
          id: { type: 'keyword' },
          name: { type: 'keyword' },
          type: { type: 'keyword' },
          url: { type: 'keyword' },
          enabled: { type: 'boolean' },
          updatedAt: { type: 'date' },
          lastSyncAt: { type: 'date' },
        },
      },
    });

    const router = core.http.createRouter();
    registerPolicyRoutes(router);
    registerArtifactRoutes(router);
    registerRollbackRoutes(router);
    registerThreatIntelRoutes(router);
    return {};
  }

  public start(core: CoreStart): Record<string, never> {
    const logger = this.initializerContext.logger.get();
    const repo = core.savedObjects.createInternalRepository([
      POLICY_SAVED_OBJECT_TYPE,
      ARTIFACT_SAVED_OBJECT_TYPE,
      FEED_SAVED_OBJECT_TYPE,
    ]);
    bindRepository(repo);

    installManagedAssets(core.opensearch.client.asInternalUser, logger).catch((err) => {
      logger.warn(`xdr_defense: managed asset installation failed: ${err?.message ?? err}`);
    });

    return {};
  }

  public stop() {}
}
