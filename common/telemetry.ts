export type TelemetryModule = 'dns' | 'network' | 'process' | 'file';

export interface TelemetryBucket { key: string; count: number; }
export interface TelemetryPoint extends TelemetryBucket { time: string; }

export interface TelemetryEvent {
  id: string;
  index: string;
  source: {
    '@timestamp': string;
    'event.type': string;
    'event.module': string;
    'host.hostname': string;
    'agent.id': string;
    payload?: Record<string, any>;
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
  facetField: string; facetLabel: string; searchHint: string;
}> = {
  dns: {
    label: 'DNS', modules: ['telemetry.dns'], entityField: 'payload.dns.question.name',
    entityLabel: 'Queried domains', facetField: 'payload.dns.response_code',
    facetLabel: 'Response codes', searchHint: 'Search domain, host or event type',
  },
  network: {
    label: 'Network', modules: ['telemetry.network'], entityField: 'payload.destination.ip',
    entityLabel: 'Destination IPs', facetField: 'payload.network.direction',
    facetLabel: 'Directions', searchHint: 'Search IP, process, host or event type',
  },
  process: {
    label: 'Process', modules: ['telemetry.process'], entityField: 'payload.process.executable',
    entityLabel: 'Executables', facetField: 'payload.process.user.name',
    facetLabel: 'Users', searchHint: 'Search executable, command, host or event type',
  },
  file: {
    label: 'File', modules: ['telemetry.file'], entityField: 'payload.file.path',
    entityLabel: 'File paths', facetField: 'payload.file.directory',
    facetLabel: 'Directories', searchHint: 'Search path, host or event type',
  },
};
