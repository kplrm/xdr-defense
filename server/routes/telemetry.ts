import { isIP } from 'net';
import { schema } from '@osd/config-schema';
import { TELEMETRY_MODULES, TelemetryBucket, TelemetryModule, TelemetryResponse } from '../../common/telemetry';

const INDEX = '.xdr-agent-telemetry-*';
const PAGE_SIZE = 25;
const MODULES = Object.keys(TELEMETRY_MODULES) as TelemetryModule[];

function buckets(aggregation: any): TelemetryBucket[] {
  return (aggregation?.buckets ?? []).map((bucket: any) => ({
    key: String(bucket.key), count: Number(bucket.doc_count ?? 0),
  }));
}

// Escape user wildcards and keep searches inside the selected module and time window.
function searchFilter(module: TelemetryModule, value: string): any {
  const escaped = value.replace(/[\\*?]/g, '\\$&');
  const fields = ['host.hostname', 'event.type'];
  if (module !== 'network') fields.push(TELEMETRY_MODULES[module].entityField);
  if (module === 'process') fields.push('payload.process.command_line', 'payload.process.name');
  if (module === 'network') fields.push('payload.process.name', 'payload.process.executable');
  const should: any[] = fields.map((field) => ({
    wildcard: { [field]: { value: `*${escaped}*`, case_insensitive: true } },
  }));
  if (isIP(value)) {
    should.push({ term: { 'payload.source.ip': value } }, { term: { 'payload.destination.ip': value } });
  }
  return { bool: { should, minimum_should_match: 1 } };
}

export function registerTelemetryRoutes(router: any): void {
  router.get({
    path: '/api/xdr-defense/telemetry',
    validate: { query: schema.object({
      module: schema.string({ validate: (value: string) => MODULES.includes(value as TelemetryModule) ? undefined : 'Unknown telemetry module' }),
      hours: schema.number({ defaultValue: 24, validate: (value: number) => [1, 24, 168].includes(value) ? undefined : 'Use 1, 24 or 168 hours' }),
      page: schema.number({ defaultValue: 1, min: 1, max: 400, validate: (value: number) => Number.isInteger(value) ? undefined : 'Expected an integer' }),
      host: schema.string({ defaultValue: '', maxLength: 256 }),
      type: schema.string({ defaultValue: '', maxLength: 256 }),
      search: schema.string({ defaultValue: '', maxLength: 128 }),
    }) },
  }, async (ctx: any, req: any, res: any) => {
    const client = ctx?.core?.opensearch?.client?.asCurrentUser;
    if (!client?.search) return res.customError({ statusCode: 503, body: { message: 'OpenSearch client unavailable.' } });

    const { module, hours, page, host, type, search } = req.query;
    const config = TELEMETRY_MODULES[module as TelemetryModule];
    const filter: any[] = [
      { range: { '@timestamp': { gte: `now-${hours}h`, lte: 'now' } } },
      { terms: { 'event.module': config.modules } },
    ];
    if (host) filter.push({ term: { 'host.hostname': host } });
    if (type) filter.push({ term: { 'event.type': type } });
    if (search.trim()) filter.push(searchFilter(module, search.trim()));

    const query = { bool: { filter } };
    const params = { index: INDEX, allow_no_indices: true, ignore_unavailable: true };
    try {
      const [summary, rows] = await Promise.all([
        client.search({ ...params, body: {
          size: 0, query,
          aggs: {
            timeline: { date_histogram: { field: '@timestamp', fixed_interval: hours === 1 ? '5m' : hours === 24 ? '1h' : '6h', min_doc_count: 0,
              extended_bounds: { min: `now-${hours}h`, max: 'now' } } },
            by_type: { terms: { field: 'event.type', size: 12 } },
            by_entity: { terms: { field: config.entityField, size: 8 } },
            by_host: { terms: { field: 'host.hostname', size: 8 } },
            by_facet: { terms: { field: config.facetField, size: 8 } },
            unique_entities: { cardinality: { field: config.entityField } },
            unique_hosts: { cardinality: { field: 'host.hostname' } },
            // The fourth metric highlights a security-relevant action for each collector.
            highlight: { filter: module === 'dns'
              ? { bool: { filter: [{ exists: { field: 'payload.dns.response_code' } }], must_not: [{ term: { 'payload.dns.response_code': 'NOERROR' } }] } }
              : module === 'network' ? { term: { 'payload.network.direction': 'outbound' } }
              : { term: { 'event.type': module === 'process' ? 'process.start' : 'file.access' } } },
          },
        } }),
        client.search({ ...params, body: {
          size: PAGE_SIZE, from: (page - 1) * PAGE_SIZE, track_total_hits: true, query,
          sort: [{ '@timestamp': { order: 'desc' } }, { id: { order: 'asc' } }],
        } }),
      ]);
      const aggs = summary?.body?.aggregations ?? {};
      const result: TelemetryResponse = {
        total: Number(rows?.body?.hits?.total?.value ?? 0), page, pageSize: PAGE_SIZE,
        events: (rows?.body?.hits?.hits ?? []).map((hit: any) => ({ id: String(hit._id), index: String(hit._index), source: hit._source })),
        timeline: (aggs.timeline?.buckets ?? []).map((bucket: any) => ({
          time: String(bucket.key_as_string), key: String(bucket.key_as_string), count: Number(bucket.doc_count ?? 0),
        })),
        byType: buckets(aggs.by_type), byEntity: buckets(aggs.by_entity),
        byHost: buckets(aggs.by_host), byFacet: buckets(aggs.by_facet),
        uniqueEntities: Number(aggs.unique_entities?.value ?? 0),
        uniqueHosts: Number(aggs.unique_hosts?.value ?? 0),
        highlightCount: Number(aggs.highlight?.doc_count ?? 0),
      };
      return res.ok({ body: result });
    } catch (error: any) {
      return res.customError({ statusCode: 500, body: { message: String(error?.message ?? error) } });
    }
  });
}
