import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../../src/core/public';

export class XdrDefensePlugin implements Plugin<Record<string, never>, Record<string, never>> {
  public setup(core: CoreSetup): Record<string, never> {
    core.application.register({
      id: 'xdrDefense',
      title: 'XDR Defense',
      category: {
        id: 'opensearch',
        label: 'OpenSearch Plugins',
        order: 2001,
      },
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart] = await core.getStartServices();
        return renderApp(coreStart, params);
      },
    });

    return {};
  }

  public start(_core: CoreStart): Record<string, never> {
    return {};
  }

  public stop() {}
}
