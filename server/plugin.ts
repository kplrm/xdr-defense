import { registerArtifactRoutes } from './routes/artifacts';
import { registerBehavioralRoutes } from './routes/behavioral';
import { registerHashRoutes } from './routes/hashes';
import { registerPolicyRoutes } from './routes/policies';
import { registerRollbackRoutes } from './routes/rollback';
import { registerYaraRoutes } from './routes/yara';

export class XdrDefenseServerPlugin {
  public setup(core: any) {
    const router = core.http.createRouter();
    registerPolicyRoutes(router);
    registerArtifactRoutes(router);
    registerRollbackRoutes(router);
    registerYaraRoutes(router);
    registerHashRoutes(router);
    registerBehavioralRoutes(router);
    return {};
  }

  public start() {
    return {};
  }

  public stop() {}
}
