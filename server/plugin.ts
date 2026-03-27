import { registerArtifactRoutes } from './routes/artifacts';
import { registerBehavioralRoutes } from './routes/behavioral';
import { ensureHashesDataView } from './lib/hashes_data_view';
import { ensureHashesIndex } from './lib/hashes_index';
import { mbAutoUpdateScheduler } from './lib/mb_auto_update';
import { registerHashRoutes } from './routes/hashes';
import { registerPolicyRoutes } from './routes/policies';
import { registerRollbackRoutes } from './routes/rollback';
import { registerSigningRoutes } from './routes/signing';
import { registerYaraRoutes } from './routes/yara';

export class XdrDefenseServerPlugin {
  public setup(core: any) {
    const bootstrapClient =
      core?.opensearch?.client?.asInternalUser ??
      core?.opensearch?.legacy?.client?.callAsInternalUser;
    if (bootstrapClient && typeof bootstrapClient === 'object') {
      ensureHashesIndex(bootstrapClient).catch((err) => {
        // Keep plugin boot resilient; routes also lazily ensure on first use.
        // eslint-disable-next-line no-console
        console.error('xdr-defense: failed to initialize hashes index', err);
      });
      mbAutoUpdateScheduler.init(bootstrapClient);
    }

    const router = core.http.createRouter();
    registerPolicyRoutes(router);
    registerArtifactRoutes(router);
    registerRollbackRoutes(router);
    registerYaraRoutes(router);
    registerHashRoutes(router);
    registerBehavioralRoutes(router);
    registerSigningRoutes(router);
    return {};
  }

  public start(core: any) {
    const repoFactory = core?.savedObjects?.createInternalRepository;
    if (typeof repoFactory === 'function') {
      const internalRepo = repoFactory.call(core.savedObjects);
      ensureHashesDataView(internalRepo).catch((err) => {
        // eslint-disable-next-line no-console
        console.error('xdr-defense: failed to install hashes data view', err);
      });
    }

    return {};
  }

  public stop() {
    mbAutoUpdateScheduler.destroy();
  }
}
