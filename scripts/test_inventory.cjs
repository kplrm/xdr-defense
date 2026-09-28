// Exercise registered handlers using the real Dashboards validation schemas.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const ts = require('typescript');
const osdRoot = process.env.OSD_ROOT || path.resolve(__dirname, '../../OpenSearch-Dashboards');
process.env.NODE_PATH = path.join(osdRoot, 'node_modules');
require('node:module').Module._initPaths();
require.extensions['.ts'] = (module, filename) => {
  const source = ts.transpileModule(readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  });
  module._compile(source.outputText, filename);
};

const { XdrDefenseServerPlugin } = require('../server/plugin.ts');
const { loadCatalog } = require('../server/lib/inventory.ts');
const { matchesCatalog } = require('../common/inventory.ts');
const routes = new Map();
new XdrDefenseServerPlugin().setup({ http: { createRouter: () => ({
  get: (config, handler) => routes.set(config.path, { config, handler }),
  // A write route is a scope regression and must fail the build.
  post: () => assert.fail('Defense must be read-only'),
  put: () => assert.fail('Defense must be read-only'),
  patch: () => assert.fail('Defense must be read-only'),
  delete: () => assert.fail('Defense must be read-only'),
}) } });
const response = {
  ok: ({ body }) => ({ status: 200, body }),
  notFound: ({ body }) => ({ status: 404, body }),
  customError: ({ statusCode, body }) => ({ status: statusCode, body }),
};
async function get(routePath, input = {}, context = {}) {
  const { config, handler } = routes.get(routePath);
  const request = {};
  for (const [key, validator] of Object.entries(config.validate)) {
    request[key] = validator.validate(input[key] || {});
  }
  return handler(context, request, response);
}
const listPath = '/api/xdr-defense/yara/rules';
const detailPath = '/api/xdr-defense/yara/rules/{name}';
const telemetryPath = '/api/xdr-defense/telemetry';

test('the documented route set is complete and only exposes reads', () => {
  assert.deepEqual([...routes.keys()].sort(), [listPath, detailPath, telemetryPath].sort());
  const docs = ['detection-content-contract.md', 'telemetry-dashboard.md']
    .map((name) => readFileSync(path.join(__dirname, '../docs', name), 'utf8')).join('\n');
  for (const route of routes.keys()) assert.ok(docs.includes(`GET ${route}`));
});

test('packaged release catalog is complete and can be paged without returning source', async () => {
  const catalog = loadCatalog();
  assert.equal(catalog.platform, 'linux');
  assert.ok(catalog.rule_count > 0);
  assert.equal(new Set(catalog.rules.map((rule) => rule.name)).size, catalog.rule_count);
  const first = await get(listPath, { query: { perPage: '1' } });
  const second = await get(listPath, { query: { perPage: '1', page: '2' } });
  assert.equal(first.status, 200);
  assert.equal(first.body.total, catalog.rule_count);
  assert.equal(first.body.rules.length, 1);
  assert.equal(first.body.rules[0].content, undefined);
  assert.notEqual(first.body.rules[0].name, second.body.rules[0].name);
  assert.deepEqual((await get(listPath, { query: { page: '100000' } })).body.rules, []);
});

test('rule search, exact source inspection and missing rules', async () => {
  const catalog = loadCatalog();
  const name = catalog.rules[0].name;
  const filtered = await get(listPath, { query: { q: name.toUpperCase() } });
  assert.ok(filtered.body.rules.some((rule) => rule.name === name));
  const detail = await get(detailPath, { params: { name } });
  assert.equal(detail.body.content, catalog.rules[0].content);
  assert.ok(detail.body.content.includes(`rule ${name}`));
  assert.equal((await get(detailPath, { params: { name: '__absent_rule__' } })).status, 404);
  assert.equal((await get(listPath, { query: { q: '__absent_rule__' } })).body.total, 0);
});

test('invalid pagination and oversized queries fail validation', async () => {
  for (const query of [{ page: 0 }, { page: 1.5 }, { perPage: 101 }, { perPage: -1 }, { q: 'x'.repeat(501) }]) {
    await assert.rejects(get(listPath, { query }));
  }
});

test('a catalog is never presented as installed without a matching report', () => {
  const catalog = loadCatalog();
  const installed = { platform: 'linux', rules_sha256: catalog.rules_sha256, rule_count: catalog.rule_count };
  assert.equal(matchesCatalog(undefined, catalog), false);
  assert.equal(matchesCatalog(installed, catalog), true);
  assert.equal(matchesCatalog({ ...installed, rules_sha256: '0'.repeat(64) }, catalog), false);
  assert.equal(matchesCatalog({ ...installed, platform: 'windows' }, catalog), false);
  assert.equal(matchesCatalog({ ...installed, rule_count: 0 }, catalog), false);
});

test('telemetry queries the selected module and returns aggregates plus paged source events', async () => {
  const calls = [];
  const client = { search: async (params) => {
    calls.push(params);
    if (params.body.size === 0) return { body: { aggregations: {
      timeline: { buckets: [{ key_as_string: '2026-09-28T21:00:00Z', doc_count: 2 }] },
      by_type: { buckets: [{ key: 'file.access', doc_count: 2 }] },
      by_entity: { buckets: [{ key: '/etc/shadow', doc_count: 2 }] },
      by_host: { buckets: [{ key: 'laptop', doc_count: 2 }] },
      by_facet: { buckets: [] },
      unique_entities: { value: 1 }, unique_hosts: { value: 1 }, highlight: { doc_count: 2 },
    } } };
    return { body: { hits: { total: { value: 2 }, hits: [{
      _id: 'agent:event', _index: '.xdr-agent-telemetry-2026-09-28',
      _source: { id: 'event', 'event.type': 'file.access', 'event.module': 'telemetry.file',
        '@timestamp': '2026-09-28T21:00:00Z', payload: { file: { path: '/etc/shadow' } } },
    }] } } };
  } };
  const context = { core: { opensearch: { client: { asCurrentUser: client } } } };
  const result = await get(telemetryPath, { query: {
    module: 'file', hours: 24, page: 2, type: 'file.access', host: 'laptop', search: 'shadow',
  } }, context);
  assert.equal(result.status, 200);
  assert.equal(result.body.total, 2);
  assert.equal(result.body.events[0].source.payload.file.path, '/etc/shadow');
  assert.equal(result.body.byType[0].key, 'file.access');
  assert.equal(result.body.uniqueEntities, 1);
  assert.equal(result.body.highlightCount, 2);
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.index, '.xdr-agent-telemetry-*');
    const filters = call.body.query.bool.filter;
    assert.deepEqual(filters[1], { terms: { 'event.module': ['telemetry.file'] } });
    assert.ok(filters.some((filter) => filter.term?.['event.type'] === 'file.access'));
    assert.ok(filters.some((filter) => filter.term?.['host.hostname'] === 'laptop'));
  }
  assert.equal(calls[1].body.from, 25);
  assert.equal(calls[0].body.aggs.by_entity.terms.field, 'payload.file.path');
  assert.equal(calls[1].body.track_total_hits, true);
});

test('telemetry validates scope and requires a scoped OpenSearch client', async () => {
  for (const query of [
    { module: 'detection.malware' }, { module: 'dns', hours: 2 },
    { module: 'dns', page: 0 }, { module: 'dns', search: 'x'.repeat(129) },
  ]) await assert.rejects(get(telemetryPath, { query }));
  const result = await get(telemetryPath, { query: { module: 'dns' } });
  assert.equal(result.status, 503);
});
