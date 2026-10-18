// Both field discovery and server searches address the stream, including every
// backing index after rollover. OpenSearch uses the same search API for streams.
export const TELEMETRY_STREAM = 'xdr-agent-telemetry';

export type TelemetryModule = 'dns' | 'network' | 'process' | 'file';

export interface TelemetryBucket { key: string; count: number; }
export interface TelemetryPoint extends TelemetryBucket { time: string; }

export interface TelemetryEvent {
  id: string;
  index: string;
  // Preserve all search-hit metadata alongside the original document.
  metadata: Record<string, unknown>;
  source: {
    '@timestamp': string;
    'event.type': string;
    'event.module': string;
    'host.hostname': string;
    'agent.id': string;
    [field: string]: any;
  };
}

export interface TelemetryResponse {
  total: number;
  page: number;
  pageSize: number;
  events: TelemetryEvent[];
  timeline: TelemetryPoint[];
  byType: TelemetryBucket[];
  byEntity: TelemetryBucket[];
  byHost: TelemetryBucket[];
  byFacet: TelemetryBucket[];
  uniqueEntities: number;
  uniqueHosts: number;
  highlightCount: number;
}

export const TELEMETRY_MODULES: Record<TelemetryModule, {
  label: string; modules: string[]; entityField: string; entityLabel: string;
  facetField: string; facetLabel: string;
}> = {
  dns: {
    label: 'DNS', modules: ['telemetry.dns'], entityField: 'dns.question.name',
    entityLabel: 'Queried domains', facetField: 'dns.response_code',
    facetLabel: 'Response codes',
  },
  network: {
    label: 'Network', modules: ['telemetry.network'], entityField: 'remote.ip',
    entityLabel: 'Remote IPs', facetField: 'network.direction',
    facetLabel: 'Directions',
  },
  process: {
    label: 'Process', modules: ['telemetry.process'], entityField: 'process.executable',
    entityLabel: 'Executables', facetField: 'process.user.name',
    facetLabel: 'Users',
  },
  file: {
    label: 'File', modules: ['telemetry.file'], entityField: 'file.path',
    entityLabel: 'File paths', facetField: 'file.directory',
    facetLabel: 'Directories',
  },
};
