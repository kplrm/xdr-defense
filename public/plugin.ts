import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart } from '../../OpenSearch-Dashboards/src/plugins/data/public';
import { PLUGIN_CATEGORY, PLUGIN_ID, PLUGIN_NAME } from '../common';

export class XdrDefensePlugin implements Plugin {
  public setup(core: CoreSetup) {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      order: 2,
      category: PLUGIN_CATEGORY,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart, depsStart] = await core.getStartServices();
        const { data } = depsStart as { data: DataPublicPluginStart };
        return renderApp(coreStart, data, params);
      },
    });
  }

  public start(_core: CoreStart) {
  }

  public stop() {}
}
