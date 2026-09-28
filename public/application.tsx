import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import { EuiSpacer, EuiTab, EuiTabs, EuiText, EuiTitle } from '@elastic/eui';
import { AppMountParameters, CoreStart } from '../../OpenSearch-Dashboards/src/core/public';
import { TELEMETRY_MODULES, TelemetryModule } from '../common/telemetry';
import { ProtectionInventory } from './components/app';
import { TelemetryExplorer } from './components/telemetry';

type DefenseTab = TelemetryModule | 'protections';
const modules: TelemetryModule[] = ['dns', 'network', 'process', 'file'];

const XdrDefenseApp = ({ http }: { http: CoreStart['http'] }) => {
  const [tab, setTab] = useState<DefenseTab>('dns');
  return <div style={{ maxWidth: 1600, margin: '0 auto', padding: 24 }}>
    <EuiTitle size="l"><h1>XDR Defense</h1></EuiTitle>
    <EuiText size="s" color="subdued">Explore endpoint telemetry and inspect installed protection content.</EuiText>
    <EuiSpacer size="m" />
    <EuiTabs>
      {modules.map((module) => <EuiTab key={module} isSelected={tab === module} onClick={() => setTab(module)}>
        {TELEMETRY_MODULES[module].label}
      </EuiTab>)}
      <EuiTab isSelected={tab === 'protections'} onClick={() => setTab('protections')}>Protections</EuiTab>
    </EuiTabs>
    <EuiSpacer size="m" />
    {tab === 'protections' ? <ProtectionInventory http={http} /> : <TelemetryExplorer http={http} module={tab} />}
  </div>;
};

export const renderApp = ({ http }: CoreStart, { element }: AppMountParameters) => {
  ReactDOM.render(<XdrDefenseApp http={http} />, element);
  return () => ReactDOM.unmountComponentAtNode(element);
};
