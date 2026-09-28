import React, { useEffect, useState } from 'react';
import {
  EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut,
  EuiCodeBlock, EuiFieldSearch, EuiFlexGroup, EuiFlexItem, EuiFlyout,
  EuiFlyoutBody, EuiFlyoutHeader, EuiFormRow, EuiPanel, EuiProgress,
  EuiSelect, EuiSpacer, EuiStat, EuiText, EuiTitle,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';
import { TELEMETRY_MODULES, TelemetryBucket, TelemetryEvent, TelemetryModule, TelemetryResponse } from '../../common/telemetry';

interface Props { http: CoreStart['http']; module: TelemetryModule; }
const display = (value: unknown): string => value === undefined || value === null || value === '' ? '—' : String(value);
const clipped = (value: unknown) => <span title={display(value)} style={{
  display: 'inline-block', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis',
  whiteSpace: 'nowrap', verticalAlign: 'bottom',
}}>{display(value)}</span>;
const address = (value: any) => value?.ip ? `${value.ip}${value.port === undefined ? '' : ':' + value.port}` : '—';
const timestamp = (value: string) => value ? new Date(value).toLocaleString() : '—';

function Timeline({ points }: { points: TelemetryResponse['timeline'] }) {
  const maximum = Math.max(1, ...points.map((point) => point.count));
  return <div role="img" aria-label="Telemetry events over time" style={{
    display: 'flex', alignItems: 'flex-end', gap: 3, height: 115, marginTop: 16,
  }}>
    {points.map((point) => <div key={point.time}
      title={`${timestamp(point.time)}: ${point.count.toLocaleString()} events`}
      style={{ flex: 1, minWidth: 2, height: `${Math.max(2, point.count / maximum * 100)}%`,
        background: point.count ? '#006bb4' : '#d3dae6', borderRadius: '2px 2px 0 0' }} />)}
  </div>;
}

function Breakdown({ title, items, onChoose }: {
  title: string; items: TelemetryBucket[]; onChoose?: (key: string) => void;
}) {
  const maximum = Math.max(1, ...items.map((item) => item.count));
  return <EuiPanel hasShadow={false} hasBorder style={{ height: '100%' }}>
    <EuiTitle size="xs"><h3>{title}</h3></EuiTitle>
    <EuiSpacer size="s" />
    {items.length === 0 && <EuiText size="s" color="subdued">No values in this time range.</EuiText>}
    {items.map((item) => <div key={item.key} style={{ marginBottom: 10 }}>
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem style={{ minWidth: 0 }}>
          {onChoose
            ? <EuiButtonEmpty size="xs" flush="left" title={item.key} onClick={() => onChoose(item.key)}>{clipped(item.key)}</EuiButtonEmpty>
            : <EuiText size="xs">{clipped(item.key)}</EuiText>}
        </EuiFlexItem>
        <EuiFlexItem grow={false}><EuiText size="xs">{item.count.toLocaleString()}</EuiText></EuiFlexItem>
      </EuiFlexGroup>
      <EuiProgress value={item.count} max={maximum} size="xs" color="primary" />
    </div>)}
  </EuiPanel>;
}

function eventColumns(module: TelemetryModule, inspect: (event: TelemetryEvent) => void): Array<EuiBasicTableColumn<TelemetryEvent>> {
  const column = (name: string, render: (source: TelemetryEvent['source']) => React.ReactNode): EuiBasicTableColumn<TelemetryEvent> => ({
    field: 'source', name, render: (source: TelemetryEvent['source']) => render(source),
  });
  const shared: Array<EuiBasicTableColumn<TelemetryEvent>> = [
    column('Time', (source) => timestamp(source['@timestamp'])),
    column('Event type', (source) => display(source['event.type'])),
    column('Host', (source) => clipped(source['host.hostname'])),
  ];
  const specific: Record<TelemetryModule, Array<EuiBasicTableColumn<TelemetryEvent>>> = {
    dns: [
      column('Question', (s) => clipped(s.payload?.dns?.question?.name)),
      column('Record', (s) => display(s.payload?.dns?.question?.type)),
      column('Response', (s) => display(s.payload?.dns?.response_code)),
      column('Answer / resolved IP', (s) => clipped(s.payload?.dns?.resolved_ips?.join(', ') || s.payload?.dns?.answers?.map((a: any) => a.data).join(', '))),
    ],
    network: [
      column('Source', (s) => address(s.payload?.source)),
      column('Destination', (s) => address(s.payload?.destination)),
      column('Transport', (s) => display(s.payload?.network?.transport)),
      column('Direction', (s) => display(s.payload?.network?.direction)),
      column('Process', (s) => clipped(s.payload?.process?.name)),
    ],
    process: [
      column('Executable', (s) => clipped(s.payload?.process?.executable)),
      column('PID', (s) => display(s.payload?.process?.pid)),
      column('Parent', (s) => clipped(s.payload?.process?.parent?.name)),
      column('User', (s) => display(s.payload?.process?.user?.name)),
      column('Command', (s) => clipped(s.payload?.process?.command_line)),
    ],
    file: [
      column('Path', (s) => clipped(s.payload?.file?.path)),
      column('Action', (s) => display(s.payload?.fim?.action || s.payload?.file?.event?.action || s.payload?.event?.action)),
      column('Owner', (s) => display(s.payload?.file?.owner)),
      column('Mode', (s) => display(s.payload?.file?.mode)),
    ],
  };
  return [...shared, ...specific[module], {
    field: 'id', name: 'Details', render: (_id: string, event: TelemetryEvent) =>
      <EuiButtonEmpty size="xs" onClick={() => inspect(event)}>View event</EuiButtonEmpty>,
  }];
}

export const TelemetryExplorer = ({ http, module }: Props) => {
  const [hours, setHours] = useState(24);
  const [host, setHost] = useState('');
  const [type, setType] = useState('');
  const [input, setInput] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<TelemetryResponse>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<TelemetryEvent>();
  const config = TELEMETRY_MODULES[module];
  const highlightLabel = { dns: 'Failed DNS answers', network: 'Outbound events',
    process: 'Process starts', file: 'File accesses' }[module];

  useEffect(() => {
    setHost(''); setType(''); setInput(''); setSearch(''); setPage(0); setData(undefined); setSelected(undefined);
  }, [module]);

  useEffect(() => {
    const timer = setTimeout(() => { setSearch(input.trim()); setPage(0); }, 300);
    return () => clearTimeout(timer);
  }, [input]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setData(undefined);
    http.get<TelemetryResponse>('/api/xdr-defense/telemetry', {
      query: { module, hours, host, type, search, page: page + 1 },
    }).then((result) => {
      if (active) { setData(result); setError(''); }
    }).catch((cause) => {
      if (active) setError(cause?.body?.message || 'Telemetry could not be loaded. Check your OpenSearch permissions and index availability.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [http, module, hours, host, type, search, page, refresh]);

  const chooseType = (value: string) => { setType(value === type ? '' : value); setPage(0); };
  const chooseEntity = (value: string) => { setInput(value); setSearch(value); setPage(0); };
  const columns = eventColumns(module, setSelected);

  return <>
    <EuiPanel hasShadow={false} hasBorder>
      <EuiFlexGroup alignItems="flexEnd" wrap gutterSize="m">
        <EuiFlexItem grow={false}><EuiFormRow label="Time range"><EuiSelect value={hours} onChange={(e) => { setHours(Number(e.target.value)); setPage(0); }}
          options={[{ value: 1, text: 'Last hour' }, { value: 24, text: 'Last 24 hours' }, { value: 168, text: 'Last 7 days' }]} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiFormRow label="Host"><EuiSelect value={host} onChange={(e) => { setHost(e.target.value); setPage(0); }}
          options={[{ value: '', text: 'All hosts' }, ...(!data?.byHost.some((item) => item.key === host) && host ? [{ value: host, text: host }] : []),
            ...(data?.byHost ?? []).map((item) => ({ value: item.key, text: item.key }))]} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiFormRow label="Event type"><EuiSelect value={type} onChange={(e) => { setType(e.target.value); setPage(0); }}
          options={[{ value: '', text: 'All types' }, ...(!data?.byType.some((item) => item.key === type) && type ? [{ value: type, text: type }] : []),
            ...(data?.byType ?? []).map((item) => ({ value: item.key, text: item.key }))]} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label="Find activity"><EuiFieldSearch fullWidth maxLength={128} value={input}
          placeholder={config.searchHint} onChange={(e) => setInput(e.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiButton onClick={() => setRefresh((n) => n + 1)} isLoading={loading}>Refresh</EuiButton></EuiFlexItem>
      </EuiFlexGroup>
    </EuiPanel>
    <EuiSpacer />
    {error && <><EuiCallOut title="Telemetry unavailable" color="danger"><p>{error}</p></EuiCallOut><EuiSpacer /></>}
    {data && <>
      {/* All cards and charts use server aggregations over the entire filtered result, not the current table page. */}
      <EuiFlexGroup wrap>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={data.total.toLocaleString()} description="Events" titleSize="m" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={data.uniqueEntities.toLocaleString()} description={`Distinct ${config.entityLabel.toLowerCase()}`} titleSize="m" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={data.uniqueHosts.toLocaleString()} description="Reporting hosts" titleSize="m" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={data.highlightCount.toLocaleString()} description={highlightLabel} titleSize="m" /></EuiPanel></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasShadow={false} hasBorder>
        <EuiTitle size="s"><h2>Activity over time</h2></EuiTitle>
        <EuiText size="xs" color="subdued">Counts across the selected time range. Hover over a bar for its interval and count.</EuiText>
        <Timeline points={data.timeline} />
        <EuiFlexGroup justifyContent="spaceBetween" responsive={false}>
          <EuiFlexItem grow={false}><EuiText size="xs" color="subdued">{data.timeline[0] && timestamp(data.timeline[0].time)}</EuiText></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiText size="xs" color="subdued">{data.timeline.length > 0 && timestamp(data.timeline[data.timeline.length - 1].time)}</EuiText></EuiFlexItem>
        </EuiFlexGroup>
      </EuiPanel>
      <EuiSpacer />
      <EuiFlexGroup wrap>
        <EuiFlexItem><Breakdown title="Event types" items={data.byType} onChoose={chooseType} /></EuiFlexItem>
        <EuiFlexItem><Breakdown title={`Top ${config.entityLabel.toLowerCase()}`} items={data.byEntity} onChoose={chooseEntity} /></EuiFlexItem>
        <EuiFlexItem><Breakdown title={config.facetLabel} items={data.byFacet} /></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasShadow={false} hasBorder>
        <EuiTitle size="s"><h2>{config.label} events</h2></EuiTitle>
        <EuiText size="xs" color="subdued">{data.total.toLocaleString()} matching events, newest first. Select an event to inspect its full source.</EuiText>
        <EuiSpacer size="m" />
        {data.total === 0 && <EuiCallOut title="No events in this range" color="primary"><p>Try a wider time range or clear the filters.</p></EuiCallOut>}
        <EuiBasicTable<TelemetryEvent> items={data.events} columns={columns} loading={loading}
          pagination={{ pageIndex: page, pageSize: data.pageSize, totalItemCount: Math.min(data.total, 10000), hidePerPageOptions: true }}
          onChange={({ page: next }: { page?: { index: number } }) => { if (next) setPage(next.index); }} />
        {data.total > 10000 && <EuiText size="xs" color="subdued">Showing the newest 10,000 events. Narrow the filters to inspect older matches.</EuiText>}
      </EuiPanel>
    </>}
    {selected && <EuiFlyout onClose={() => setSelected(undefined)} size="l" aria-labelledby="telemetry-event-title">
      <EuiFlyoutHeader hasBorder><EuiTitle size="m"><h2 id="telemetry-event-title">{display(selected.source['event.type'])}</h2></EuiTitle></EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiText size="s"><p>{timestamp(selected.source['@timestamp'])} · {display(selected.source['host.hostname'])}<br />
          Agent: {display(selected.source['agent.id'])}<br />Index: {selected.index}</p></EuiText>
        <EuiSpacer />
        <EuiCodeBlock language="json" isCopyable fontSize="s">{JSON.stringify(selected.source, null, 2)}</EuiCodeBlock>
      </EuiFlyoutBody>
    </EuiFlyout>}
  </>;
};
