// Exercise the registered route with Dashboards' real validation schemas.
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
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
  });
  module._compile(source.outputText, filename);
};

const { XdrDefenseServerPlugin } = require('../server/plugin.ts');
const routePath = '/api/xdr-defense/telemetry/search';
const routes = new Map();
new XdrDefenseServerPlugin().setup({ http: { createRouter: () => ({
  post: (config, handler) => routes.set(config.path, { config, handler }),
  get: () => assert.fail('Only telemetry search should be registered'),
  put: () => assert.fail('Defense must not expose writes'),
  patch: () => assert.fail('Defense must not expose writes'),
  delete: () => assert.fail('Defense must not expose writes'),
}) } });
const response = {
  ok: ({ body }) => ({ status: 200, body }),
  customError: ({ statusCode, body }) => ({ status: statusCode, body }),
};
const base = {
  module: 'dns',
  from: '2026-09-28T20:00:00.000Z',
  to: '2026-09-28T22:00:00.000Z',
  page: 2,
  query: { bool: { filter: [{ term: { 'host.hostname': 'laptop' } }] } },
};
async function search(body = base, context = {}) {
  const route = routes.get(routePath);
  return route.handler(context, { body: route.config.validate.body.validate(body) }, response);
}

test('only the documented read-only telemetry search route remains', () => {
  assert.deepEqual([...routes.keys()], [routePath]);
  const doc = readFileSync(path.join(__dirname, '../README.md'), 'utf8');
  assert.ok(doc.includes(`POST ${routePath}`));
});

test('time, module and compiled Discover filters scope every search', async () => {
  const calls = [];
  const client = { search: async (params) => {
    calls.push(params);
    if (params.body.size === 0) return { body: { aggregations: {
      timeline: { buckets: [{ key_as_string: base.from, doc_count: 2 }] },
      by_type: { buckets: [{ key: 'dns.query', doc_count: 2 }] },
      by_entity: { buckets: [{ key: 'example.org', doc_count: 2 }] },
      by_host: { buckets: [{ key: 'laptop', doc_count: 2 }] },
      by_facet: { buckets: [] },
      unique_entities: { value: 1 }, unique_hosts: { value: 1 }, highlight: { doc_count: 0 },
    } } };
    return { body: { hits: { total: { value: 2 }, hits: [{
      _id: 'agent:event', _index: '.ds-xdr-agent-telemetry-000001',
      _score: null, sort: [1790625600000, 'event'], _ignored: ['payload.large'],
      fields: { 'host.hostname': ['laptop'] },
      _source: { id: 'event', 'event.type': 'dns.query', 'event.module': 'telemetry.dns',
        '@timestamp': base.from, payload: { dns: { question: { name: 'example.org' } } } },
    }] } } };
  } };
  const context = { core: { opensearch: { client: { asCurrentUser: client } } } };
  const result = await search(base, context);
  assert.equal(result.status, 200);
  assert.equal(result.body.total, 2);
  assert.equal(result.body.events[0].source.payload.dns.question.name, 'example.org');
  // Keep metadata available to both inspection views without altering _source.
  assert.deepEqual(result.body.events[0].metadata, {
    _id: 'agent:event', _index: '.ds-xdr-agent-telemetry-000001',
    _score: null, sort: [1790625600000, 'event'], _ignored: ['payload.large'],
    fields: { 'host.hostname': ['laptop'] },
  });
  assert.equal(result.body.events[0].source.id, 'event');
  assert.equal(result.body.byType[0].key, 'dns.query');
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.index, 'xdr-agent-telemetry');
    const filters = call.body.query.bool.filter;
    assert.deepEqual(filters[0], { range: { '@timestamp': { gte: base.from, lte: base.to } } });
    assert.deepEqual(filters[1], { terms: { 'event.module': ['telemetry.dns'] } });
    assert.deepEqual(filters[2], base.query);
  }
  assert.equal(calls[1].body.from, 25);
  assert.equal(calls[0].body.aggs.by_entity.terms.field, 'payload.dns.question.name');
  assert.equal(calls[1].body.track_total_hits, true);
  assert.equal(calls[1].body.sort[1].id.unmapped_type, 'keyword');
});

test('invalid scope and time are rejected; a scoped client is required', async () => {
  for (const body of [
    { ...base, module: 'detection.malware' }, { ...base, page: 0 },
    { ...base, page: 1.5 }, { ...base, from: base.to, to: base.from },
    { ...base, from: '2026-09-31T20:00:00.000Z' }, { ...base, query: 'uncompiled' },
  ]) {
    if (body.module === 'detection.malware' || body.page === 0 || body.page === 1.5) {
      await assert.rejects(search(body));
    } else {
      const context = { core: { opensearch: { client: { asCurrentUser: { search: async () => ({}) } } } } };
      assert.equal((await search(body, context)).status, 400);
    }
  }
  assert.equal((await search()).status, 503);
});
