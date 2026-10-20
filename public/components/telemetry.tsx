import React, { useEffect, useState } from 'react';
import {
  EuiBasicTable, EuiBasicTableColumn, EuiButtonEmpty, EuiButtonIcon, EuiCallOut, EuiCodeBlock,
  EuiFieldSearch, EuiFlexGroup, EuiFlexItem, EuiFlyout, EuiFlyoutBody, EuiFlyoutHeader,
  EuiLink, EuiPanel, EuiPopover, EuiProgress, EuiSpacer, EuiStat, EuiTab, EuiTabs, EuiText, EuiTitle,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart, DataView } from '../../../OpenSearch-Dashboards/src/plugins/data/public';
import { TELEMETRY_MODULES, TelemetryBucket, TelemetryEvent, TelemetryModule, TelemetryResponse } from '../../common/telemetry';
import './telemetry.scss';

type FilterValue = string | number | boolean;
type AddFilter = (field: string, value: FilterValue) => void;
interface Props {
  http: CoreStart['http']; data: DataPublicPluginStart; dataView: DataView;
  module: TelemetryModule; revision: number; onFilter: AddFilter;
}
interface FieldValue { field: string; value: FilterValue | null | undefined; label?: string; filterable?: boolean; }
const display = (value: unknown): string => value === undefined || value === null || value === '' ? '—' : String(value);
const timestamp = (value: string) => value ? new Date(value).toLocaleString() : '—';
const visible = (value: unknown) => value !== undefined && value !== null && value !== '';

function FilterCell({ values, onFilter, separator = ', ', expandable = false }: {
  values: FieldValue[]; onFilter: AddFilter; separator?: string; expandable?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const entries = values.filter((item) => visible(item.value));
  if (!entries.length) return <span>—</span>;
  const fullText = entries.map((item) => item.label ?? display(item.value)).join(separator);
  const links = entries.map((item, index) => <React.Fragment key={`${item.field}-${index}`}>
    {index > 0 && separator}
    <EuiLink title={`Filter: ${item.field} is ${display(item.value)}`}
      onClick={() => onFilter(item.field, item.value as FilterValue)}>
      {item.label ?? display(item.value)}
    </EuiLink>
  </React.Fragment>);
  if (!expandable) return <span>{links}</span>;
  return <div className="xdrDefenseCell">
    <span className="xdrDefenseCell__preview">{links}</span>
    <EuiPopover isOpen={isOpen} closePopover={() => setIsOpen(false)} anchorPosition="downLeft"
      button={<EuiButtonIcon className="xdrDefenseCell__expand" size="xs" iconType="popout"
        aria-label="Show full cell value" title="Show full cell value" onClick={() => setIsOpen(!isOpen)} />}>
      <div className="xdrDefenseCell__fullValue">{fullText}</div>
    </EuiPopover>
  </div>;
}

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

function Breakdown({ title, field, items, onFilter }: {
  title: string; field: string; items: TelemetryBucket[]; onFilter: AddFilter;
}) {
  const maximum = Math.max(1, ...items.map((item) => item.count));
  return <EuiPanel hasShadow={false} hasBorder style={{ height: '100%' }}>
    <EuiTitle size="xs"><h3>{title}</h3></EuiTitle>
    <EuiSpacer size="s" />
    {items.length === 0 && <EuiText size="s" color="subdued">No values in this time range.</EuiText>}
    {items.map((item) => <div key={item.key} style={{ marginBottom: 10 }}>
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem style={{ minWidth: 0 }}>
          <FilterCell values={[{ field, value: item.key }]} onFilter={onFilter} />
        </EuiFlexItem>
        <EuiFlexItem grow={false}><EuiText size="xs">{item.count.toLocaleString()}</EuiText></EuiFlexItem>
      </EuiFlexGroup>
      <EuiProgress value={item.count} max={maximum} size="xs" color="primary" />
    </div>)}
  </EuiPanel>;
}

function eventColumns(module: TelemetryModule, onFilter: AddFilter, inspect: (event: TelemetryEvent) => void): Array<EuiBasicTableColumn<TelemetryEvent>> {
  const cell = (field: string, value: FieldValue['value'], label?: string) =>
    <FilterCell values={[{ field, value, label }]} onFilter={onFilter} expandable />;
  const column = (name: string, render: (source: TelemetryEvent['source']) => React.ReactNode): EuiBasicTableColumn<TelemetryEvent> => ({
    field: 'source', name, render: (source: TelemetryEvent['source']) => render(source),
  });
  const common: Array<EuiBasicTableColumn<TelemetryEvent>> = [
    column('Time', (s) => cell('@timestamp', s['@timestamp'], timestamp(s['@timestamp']))),
    column('Event type', (s) => cell('event.type', s['event.type'])),
    column('Host', (s) => cell('host.hostname', s['host.hostname'])),
  ];
  const specific: Record<TelemetryModule, Array<EuiBasicTableColumn<TelemetryEvent>>> = {
    dns: [
      column('Question', (s) => cell('dns.question.name', s.dns.question?.name)),
      column('Record', (s) => cell('dns.question.type', s.dns.question?.type)),
      column('Response', (s) => cell('dns.response_code', s.dns.response_code)),
      column('Answer / resolved IP', (s) => {
        const answers = s.dns.answers;
        const values: FieldValue[] = Array.isArray(answers) && answers.length
          ? answers.map((answer: any) => ({ field: 'dns.answers.data', value: answer.data }))
          : (s.dns.resolved_ips ?? []).map((ip: string) => ({ field: 'dns.resolved_ips', value: ip }));
        return <FilterCell values={values} onFilter={onFilter} expandable />;
      }),
    ],
    network: [
      column('Local', (s) => <FilterCell onFilter={onFilter} separator="" expandable values={[
        { field: 'local.ip', value: s.local?.ip },
        { field: 'local.port', value: s.local?.port, label: s.local?.port === undefined ? '' : `:${s.local.port}` },
      ]} />),
      column('Remote', (s) => <FilterCell onFilter={onFilter} separator="" expandable values={[
        { field: 'remote.ip', value: s.remote?.ip },
        { field: 'remote.port', value: s.remote?.port, label: s.remote?.port === undefined ? '' : `:${s.remote.port}` },
      ]} />),
      column('Transport', (s) => cell('network.transport', s.network?.transport)),
      column('Direction', (s) => cell('network.direction', s.network?.direction)),
      column('Process', (s) => cell('process.name', s.process?.name)),
    ],
    process: [
      column('Executable', (s) => cell('process.executable', s.process.executable)),
      column('PID', (s) => cell('process.pid', s.process.pid)),
      column('Parent', (s) => cell('process.parent.name', s.process.parent?.name)),
      column('User', (s) => cell('process.user.name', s.process.user?.name)),
      column('Command', (s) => cell('process.command_line', s.process.command_line)),
    ],
    file: [
      column('Path', (s) => cell('file.path', s.file?.path)),
      column('Action', (s) => {
        const action = s.fim?.action ?? s.file?.event?.action ?? s.event?.action;
        const field = s.fim?.action !== undefined ? 'fim.action'
          : s.file?.event?.action !== undefined ? 'file.event.action' : 'event.action';
        return cell(field, action);
      }),
      column('Owner', (s) => cell('file.owner', s.file?.owner)),
      column('Mode', (s) => cell('file.mode', s.file?.mode)),
    ],
  };
  return [...common, ...specific[module], {
    field: 'id', name: 'Details', render: (_id: string, event: TelemetryEvent) =>
      <EuiButtonEmpty size="xs" onClick={() => inspect(event)}>View event</EuiButtonEmpty>,
  }];
}

function flatten(value: any, prefix = '', rows: FieldValue[] = []): FieldValue[] {
  if (value && typeof value === 'object' && Object.keys(value).length === 0) {
    rows.push({ field: prefix, value: JSON.stringify(value), filterable: false });
  } else if (Array.isArray(value)) {
    value.forEach((part) => flatten(part, prefix, rows));
  } else if (value && typeof value === 'object') {
    Object.entries(value).forEach(([name, part]) => flatten(part, prefix ? `${prefix}.${name}` : name, rows));
  } else if (prefix) {
    rows.push({ field: prefix, value: value === null || value === '' ? JSON.stringify(value) : value,
      filterable: value !== null && value !== '' });
  }
  return rows;
}

function EventDetails({ event, onClose, onFilter }: {
  event: TelemetryEvent; onClose: () => void; onFilter: AddFilter;
}) {
  const [view, setView] = useState<'table' | 'json'>('table');
  const [search, setSearch] = useState('');
  const query = search.trim().toLowerCase();
  // Metadata is inspectable, but values such as sort and _score are not filters.
  const metadata = event.metadata ?? { _id: event.id, _index: event.index };
  const document = { ...metadata, _source: event.source };
  const metadataRows: FieldValue[] = Object.entries(metadata).map(([field, value]) => ({
    field, value: typeof value === 'string' ? value : JSON.stringify(value), filterable: false,
  }));
  const rows = [...metadataRows, ...flatten(event.source)].filter((row) =>
    !query || row.field.toLowerCase().includes(query) || display(row.value).toLowerCase().includes(query));
  const columns: Array<EuiBasicTableColumn<FieldValue>> = [
    { field: 'field', name: 'Field', render: (field: string) => <code>{field}</code> },
    { field: 'value', name: 'Value', render: (_value: FilterValue, row: FieldValue) =>
      row.filterable === false ? <code>{row.value}</code> : <FilterCell values={[row]} onFilter={onFilter} expandable /> },
  ];
  return <EuiFlyout onClose={onClose} size="l" aria-labelledby="telemetry-event-title">
    <EuiFlyoutHeader hasBorder><EuiTitle size="m"><h2 id="telemetry-event-title">{display(event.source['event.type'])}</h2></EuiTitle></EuiFlyoutHeader>
    <EuiFlyoutBody>
      <EuiFieldSearch fullWidth placeholder="Search fields or values" aria-label="Search event fields and values"
        value={search} onChange={(change) => setSearch(change.target.value)} />
      <EuiSpacer size="m" />
      <EuiTabs>
        <EuiTab isSelected={view === 'table'} onClick={() => setView('table')}>Table</EuiTab>
        <EuiTab isSelected={view === 'json'} onClick={() => setView('json')}>JSON</EuiTab>
      </EuiTabs>
      <EuiSpacer size="m" />
      {view === 'table' ? <>
        <EuiBasicTable<FieldValue> items={rows} columns={columns} />
        {rows.length === 0 && <EuiText size="s" color="subdued">No matching fields or values.</EuiText>}
      </> : <EuiCodeBlock language="json" isCopyable fontSize="s">{JSON.stringify(document, null, 2)}</EuiCodeBlock>}
    </EuiFlyoutBody>
  </EuiFlyout>;
}

export const TelemetryExplorer = ({ http, data: dataPlugin, dataView, module, revision, onFilter }: Props) => {
  const [page, setPage] = useState(0);
  const [response, setResponse] = useState<TelemetryResponse>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<TelemetryEvent>();
  const config = TELEMETRY_MODULES[module];
  const highlightLabel = { dns: 'Failed DNS answers', network: 'Outbound events',
    process: 'Process starts', file: 'File accesses' }[module];

  useEffect(() => { setPage(0); setSelected(undefined); }, [module, revision]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setResponse(undefined);
    try {
      const time = dataPlugin.query.timefilter.timefilter.getTime();
      const query = dataPlugin.query.getOpenSearchQuery(dataView as any);
      http.post<TelemetryResponse>('/api/xdr-defense/telemetry/search', {
        body: JSON.stringify({ module, from: time.from, to: time.to, page: page + 1, query }),
      }).then((result) => {
        if (active) { setResponse(result); setError(''); }
      }).catch((cause) => {
        if (active) setError(cause?.body?.message || 'Telemetry could not be loaded.');
      }).finally(() => { if (active) setLoading(false); });
    } catch (cause: any) {
      if (active) { setError(cause?.message || 'The query is invalid.'); setLoading(false); }
    }
    return () => { active = false; };
  }, [http, dataPlugin, dataView, module, page, revision]);

  return <>
    {error && <><EuiCallOut title="Telemetry unavailable" color="danger"><p>{error}</p></EuiCallOut><EuiSpacer /></>}
    {response && <>
      {/* Cards and charts summarize all filtered events, rather than just the visible table page. */}
      <EuiFlexGroup wrap>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={response.total.toLocaleString()} description="Events" titleSize="m" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={response.uniqueEntities.toLocaleString()} description={`Distinct ${config.entityLabel.toLowerCase()}`} titleSize="m" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={response.uniqueHosts.toLocaleString()} description="Reporting hosts" titleSize="m" /></EuiPanel></EuiFlexItem>
        <EuiFlexItem><EuiPanel hasShadow={false} hasBorder><EuiStat title={response.highlightCount.toLocaleString()} description={highlightLabel} titleSize="m" /></EuiPanel></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasShadow={false} hasBorder>
        <EuiTitle size="s"><h2>Activity over time</h2></EuiTitle>
        <EuiText size="xs" color="subdued">Counts across the selected time range. Hover over a bar for its interval and count.</EuiText>
        <Timeline points={response.timeline} />
        <EuiFlexGroup justifyContent="spaceBetween" responsive={false}>
          <EuiFlexItem grow={false}><EuiText size="xs" color="subdued">{response.timeline[0] && timestamp(response.timeline[0].time)}</EuiText></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiText size="xs" color="subdued">{response.timeline.length > 0 && timestamp(response.timeline[response.timeline.length - 1].time)}</EuiText></EuiFlexItem>
        </EuiFlexGroup>
      </EuiPanel>
      <EuiSpacer />
      <EuiFlexGroup wrap>
        <EuiFlexItem><Breakdown title="Event types" field="event.type" items={response.byType} onFilter={onFilter} /></EuiFlexItem>
        <EuiFlexItem><Breakdown title={`Top ${config.entityLabel.toLowerCase()}`} field={config.entityField} items={response.byEntity} onFilter={onFilter} /></EuiFlexItem>
        <EuiFlexItem><Breakdown title={config.facetLabel} field={config.facetField} items={response.byFacet} onFilter={onFilter} /></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasShadow={false} hasBorder>
        <EuiTitle size="s"><h2>{config.label} events</h2></EuiTitle>
        <EuiText size="xs" color="subdued">{response.total.toLocaleString()} matching events, newest first. Select a value to add a filter, or view the full event.</EuiText>
        <EuiSpacer size="m" />
        {response.total === 0 && <EuiCallOut title="No events in this range" color="primary"><p>Widen the time range or clear filters.</p></EuiCallOut>}
        <EuiBasicTable<TelemetryEvent> className="xdrDefenseEventsTable" tableLayout="fixed"
          items={response.events} columns={eventColumns(module, onFilter, setSelected)} loading={loading}
          pagination={{ pageIndex: page, pageSize: response.pageSize, totalItemCount: Math.min(response.total, 10000), hidePerPageOptions: true }}
          onChange={({ page: next }: { page?: { index: number } }) => { if (next) setPage(next.index); }} />
        {response.total > 10000 && <EuiText size="xs" color="subdued">Showing the newest 10,000 events. Narrow the filters to inspect older matches.</EuiText>}
      </EuiPanel>
    </>}
    {selected && <EventDetails key={selected.id} event={selected} onClose={() => setSelected(undefined)} onFilter={onFilter} />}
  </>;
};
