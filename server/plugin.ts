import { registerInventoryRoutes } from './routes/inventory';
import { registerTelemetryRoutes } from './routes/telemetry';

/** Defense reads the catalog shipped with an agent release. */
export class XdrDefenseServerPlugin {
  public setup(core: any) {
    registerInventoryRoutes(core.http.createRouter());
    registerTelemetryRoutes(core.http.createRouter());
    return {};
  }

  public start() { return {}; }
  public stop() {}
}
