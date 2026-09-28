import { registerTelemetryRoutes } from './routes/telemetry';

/** Read-only telemetry search for the current Dashboards user. */
export class XdrDefenseServerPlugin {
  public setup(core: any) {
    registerTelemetryRoutes(core.http.createRouter());
    return {};
  }

  public start() { return {}; }
  public stop() {}
}
