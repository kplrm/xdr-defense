import React, { useCallback, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { I18nProvider } from '@osd/i18n/react';
import { EuiCallOut, EuiLoadingSpinner, EuiSpacer, EuiTab, EuiTabs, EuiText, EuiTitle } from '@elastic/eui';
import { AppMountParameters, CoreStart } from '../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart, DataView } from '../../OpenSearch-Dashboards/src/plugins/data/public';
import { TELEMETRY_MODULES, TelemetryModule } from '../common/telemetry';
import { TelemetryExplorer } from './components/telemetry';

const modules: TelemetryModule[] = ['dns', 'network', 'process', 'file'];

const XdrDefenseApp = ({ http, data }: { http: CoreStart['http']; data: DataPublicPluginStart }) => {
  const [tab, setTab] = useState<TelemetryModule>('dns');
  const [dataView, setDataView] = useState<DataView>();
  const [viewError, setViewError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    // A temporary data view supplies the same KQL fields and filter editor as Discover.
    data.dataViews.create({ title: 'xdr-agent-telemetry,.xdr-agent-telemetry-*', timeFieldName: '@timestamp' })
      .then((view) => { if (active) setDataView(view); })
      .catch(() => { if (active) setViewError('Telemetry fields could not be loaded. Check access to the telemetry indices.'); });
    const current = data.query.queryString.getQuery();
    if (current.language !== 'kuery') data.query.queryString.setQuery({ query: '', language: 'kuery' });
    return () => { active = false; };
  }, [data]);

  useEffect(() => {
    const update = () => setRevision((value) => value + 1);
    const state = data.query.state$.subscribe(update);
    const automatic = data.query.timefilter.timefilter.getAutoRefreshFetch$().subscribe(update);
    return () => { state.unsubscribe(); automatic.unsubscribe(); };
  }, [data]);

  const addFilter = useCallback((field: string, value: string | number | boolean) => {
    if (!dataView) return;
    // Native FilterBar pills accept the same phrase-filter shape used by Discover.
    data.query.filterManager.addFilters([{
      meta: { index: dataView.id, type: 'phrase', key: field, value: String(value),
        params: { query: value }, alias: null, disabled: false, negate: false },
      query: { match_phrase: { [field]: value } },
      $state: { store: 'appState' as any },
    }]);
  }, [data, dataView]);

  const SearchBar = data.ui.SearchBar;
  return <div style={{ maxWidth: 1600, margin: '0 auto', padding: 24 }}>
    <EuiTitle size="l"><h1>XDR Defense</h1></EuiTitle>
    <EuiText size="s" color="subdued">Explore endpoint DNS, network, process and file telemetry.</EuiText>
    <EuiSpacer size="m" />
    {viewError && <><EuiCallOut title={viewError} color="danger" /><EuiSpacer /></>}
    {!dataView && !viewError && <EuiLoadingSpinner />}
    {dataView && <>
      <SearchBar appName="xdrDefense" indexPatterns={[dataView]} useDefaultBehaviors
        showDatePicker showFilterBar showQueryBar showQueryInput showSaveQuery={false}
        onQuerySubmit={() => setRevision((value) => value + 1)} />
      <EuiSpacer size="m" />
      <EuiTabs>
        {modules.map((module) => <EuiTab key={module} isSelected={tab === module} onClick={() => setTab(module)}>
          {TELEMETRY_MODULES[module].label}
        </EuiTab>)}
      </EuiTabs>
      <EuiSpacer size="m" />
      <TelemetryExplorer http={http} data={data} dataView={dataView} module={tab}
        revision={revision} onFilter={addFilter} />
    </>}
  </div>;
};

export const renderApp = ({ http }: CoreStart, data: DataPublicPluginStart, { element }: AppMountParameters) => {
  // Dashboards' SearchBar and EUI components use React Intl during render.
  ReactDOM.render(<I18nProvider><XdrDefenseApp http={http} data={data} /></I18nProvider>, element);
  return () => ReactDOM.unmountComponentAtNode(element);
};
