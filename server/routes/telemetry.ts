// Dashboards supplies date math at runtime; this external plugin has no local type package.
const dateMath = require('@elastic/datemath');
import { schema } from '@osd/config-schema';
import { TELEMETRY_MODULES, TelemetryBucket, TelemetryModule, TelemetryResponse } from '../../common/telemetry';

const INDEX = 'xdr-agent-telemetry';
const PAGE_SIZE = 25;
const MODULES = Object.keys(TELEMETRY_MODULES) as TelemetryModule[];

function buckets(aggregation: any): TelemetryBucket[] {
  return (aggregation?.buckets ?? []).map((bucket: any) => ({
    key: String(bucket.key), count: Number(bucket.doc_count ?? 0),
  }));
}

function intervalFor(rangeMs: number): string {
  // Keep roughly 30–50 bars for custom absolute and relative ranges.
  const intervals: Array<[number, string]> = [
    [60_000, '1m'], [300_000, '5m'], [900_000, '15m'], [3_600_000, '1h'],
    [21_600_000, '6h'], [86_400_000, '1d'], [604_800_000, '7d'],
    [2_592_000_000, '30d'], [31_536_000_000, '365d'],
  ];
  return intervals.find(([duration]) => rangeMs / duration <= 50)?.[1] ?? '365d';
}

export function registerTelemetryRoutes(router: any): void {
  router.post({
    path: '/api/xdr-defense/telemetry/search',
    validate: { body: schema.object({
      module: schema.string({ validate: (value: string) => MODULES.includes(value as TelemetryModule) ? undefined : 'Unknown telemetry module' }),
      from: schema.string({ minLength: 1, maxLength: 128 }),
      to: schema.string({ minLength: 1, maxLength: 128 }),
      page: schema.number({ defaultValue: 1, min: 1, max: 400, validate: (value: number) => Number.isInteger(value) ? undefined : 'Expected an integer' }),
      query: schema.any(),
    }) },
  }, async (ctx: any, req: any, res: any) => {
    const client = ctx?.core?.opensearch?.client?.asCurrentUser;
    if (!client?.search) return res.customError({ statusCode: 503, body: { message: 'OpenSearch client unavailable.' } });

    const { module, from, to, page, query: userQuery } = req.body;
    const start = dateMath.parse(from);
    const end = dateMath.parse(to, { roundUp: true });
    if (!start?.isValid() || !end?.isValid() || start.valueOf() >= end.valueOf()) {
      return res.customError({ statusCode: 400, body: { message: 'Invalid time range.' } });
    }
    if (!userQuery || typeof userQuery !== 'object' || Array.isArray(userQuery) ||
        JSON.stringify(userQuery).length > 32_000 || userQuery.type === 'unsupported') {
      return res.customError({ statusCode: 400, body: { message: 'Invalid query.' } });
    }

    const config = TELEMETRY_MODULES[module as TelemetryModule];
    const startIso = start.toISOString();
    const endIso = end.toISOString();
    const query = { bool: { filter: [
      { range: { '@timestamp': { gte: startIso, lte: endIso } } },
      { terms: { 'event.module': config.modules } },
      // Discover compiles KQL and enabled filter pills; the server enforces index, time and module scope.
      userQuery,
    ] } };
    const params = { index: INDEX, allow_no_indices: true, ignore_unavailable: true };
    try {
      const [summary, rows] = await Promise.all([
        client.search({ ...params, body: {
          size: 0, query,
          aggs: {
            timeline: { date_histogram: { field: '@timestamp', fixed_interval: intervalFor(end.valueOf() - start.valueOf()), min_doc_count: 0,
              extended_bounds: { min: startIso, max: endIso } } },
            by_type: { terms: { field: 'event.type', size: 12 } },
            by_entity: { terms: { field: config.entityField, size: 8 } },
            by_host: { terms: { field: 'host.hostname', size: 8 } },
            by_facet: { terms: { field: config.facetField, size: 8 } },
            unique_entities: { cardinality: { field: config.entityField } },
            unique_hosts: { cardinality: { field: 'host.hostname' } },
            highlight: { filter: module === 'dns'
              ? { bool: { filter: [{ exists: { field: 'payload.dns.response_code' } }], must_not: [{ term: { 'payload.dns.response_code': 'NOERROR' } }] } }
              : module === 'network' ? { term: { 'payload.network.direction': 'outbound' } }
              : { term: { 'event.type': module === 'process' ? 'process.start' : 'file.access' } } },
          },
        } }),
        client.search({ ...params, body: {
          size: PAGE_SIZE, from: (page - 1) * PAGE_SIZE, track_total_hits: true, query,
          sort: [{ '@timestamp': { order: 'desc' } }, { id: { order: 'asc', unmapped_type: 'keyword' } }],
        } }),
      ]);
      const aggs = summary?.body?.aggregations ?? {};
      const result: TelemetryResponse = {
        total: Number(rows?.body?.hits?.total?.value ?? 0), page, pageSize: PAGE_SIZE,
        events: (rows?.body?.hits?.hits ?? []).map((hit: any) => {
          const { _source, ...metadata } = hit;
          return { id: String(hit._id), index: String(hit._index), source: _source, metadata };
        }),
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
