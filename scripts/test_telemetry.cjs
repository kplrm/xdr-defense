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
      _score: null, sort: [1790625600000, 1], _ignored: ['large'],
      fields: { 'host.hostname': ['laptop'] },
      _source: { 'event.type': 'dns.query', 'event.module': 'telemetry.dns',
        '@timestamp': base.from, dns: { question: { name: 'example.org' } } },
    }] } } };
  } };
  const context = { core: { opensearch: { client: { asCurrentUser: client } } } };
  const result = await search(base, context);
  assert.equal(result.status, 200);
  assert.equal(result.body.total, 2);
  assert.equal(result.body.events[0].source.dns.question.name, 'example.org');
  // Keep metadata available to both inspection views without altering _source.
  assert.deepEqual(result.body.events[0].metadata, {
    _id: 'agent:event', _index: '.ds-xdr-agent-telemetry-000001',
    _score: null, sort: [1790625600000, 1], _ignored: ['large'],
    fields: { 'host.hostname': ['laptop'] },
  });
  assert.equal(result.body.events[0].id, 'agent:event');
  assert.equal(Object.hasOwn(result.body.events[0].source, 'id'), false);
  assert.equal(Object.hasOwn(result.body.events[0].source, '_id'), false);
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
  assert.equal(calls[0].body.aggs.by_entity.terms.field, 'dns.question.name');
  assert.equal(calls[1].body.track_total_hits, true);
  assert.deepEqual(calls[1].body.sort, [{ '@timestamp': { order: 'desc' } }, { _doc: { order: 'asc' } }]);
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

test('network summaries and filters use the remote host endpoint', async () => {
  const calls = [];
  const client = { search: async (params) => { calls.push(params); return { body: {} }; } };
  const query = { term: { 'local.ip': '2001:db8::1' } };
  const result = await search({ ...base, module: 'network', query }, {
    core: { opensearch: { client: { asCurrentUser: client } } },
  });
  assert.equal(result.status, 200);
  assert.equal(calls[0].body.aggs.by_entity.terms.field, 'remote.ip');
  assert.equal(calls[0].body.aggs.unique_entities.cardinality.field, 'remote.ip');
  for (const call of calls) assert.deepEqual(call.body.query.bool.filter[2], query);
});

test('telemetry tabs render their own events, including network events without process attribution', async () => {
  const React = require(path.join(osdRoot, 'node_modules/react'));
  const renderer = require(path.join(osdRoot, 'node_modules/react-test-renderer'));
  const { Module } = require('node:module');
  // Keep EUI lightweight while exercising the actual table column renderers.
  const eui = new Proxy({
    EuiBasicTable: ({ items, columns }) => React.createElement('table', null,
      items.flatMap((item, row) => columns.map((column, cell) => React.createElement('td', {
        key: `${row}-${cell}`,
      }, column.render ? column.render(item[column.field], item) : item[column.field])))),
  }, {
    get: (components, name) => components[name] ?? (components[name] = (props) =>
      React.createElement(name, props, props.children)),
  });
  function loadComponent(relative, mocks) {
    const filename = path.join(__dirname, '..', relative);
    const loaded = new Module(filename, module);
    loaded.filename = filename;
    loaded.paths = Module._nodeModulePaths(path.dirname(filename));
    loaded.require = (name) => Object.hasOwn(mocks, name)
      ? mocks[name] : Module.prototype.require.call(loaded, name);
    loaded._compile(ts.transpileModule(readFileSync(filename, 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020,
        jsx: ts.JsxEmit.React, esModuleInterop: true },
    }).outputText, filename);
    return loaded.exports;
  }
  let view;
  const explorer = loadComponent('public/components/telemetry.tsx', {
    react: React, '@elastic/eui': eui, './telemetry.scss': {},
  });
  const app = loadComponent('public/application.tsx', {
    react: React, '@elastic/eui': eui, './components/telemetry': explorer,
    '@osd/i18n/react': { I18nProvider: React.Fragment },
    'react-dom': {
      render: (element) => { view = renderer.create(element); },
      unmountComponentAtNode: () => view.unmount(),
    },
  });
  const requests = [];
  const http = { post: (_route, { body }) => new Promise((resolve) => {
    requests.push({ module: JSON.parse(body).module, resolve });
  }) };
  const subscription = { subscribe: () => ({ unsubscribe() {} }) };
  const data = {
    dataViews: { create: async () => ({ id: 'telemetry' }) },
    ui: { SearchBar: () => null },
    query: {
      state$: subscription,
      queryString: { getQuery: () => ({ language: 'kuery', query: '' }) },
      getOpenSearchQuery: () => ({ match_all: {} }),
      timefilter: { timefilter: {
        getTime: () => ({ from: base.from, to: base.to }),
        getAutoRefreshFetch$: () => subscription,
      } },
    },
  };
  const fixtures = {
    dns: { dns: { question: { name: 'example.org' } } },
    network: { local: { ip: '192.0.2.1' }, remote: { ip: '198.51.100.1' } },
    process: { process: { name: 'example', executable: '/usr/bin/example', pid: 42 } },
    file: { file: { path: '/tmp/example' } },
  };
  let unmount;
  try {
    await renderer.act(async () => { unmount = app.renderApp({ http }, data, { element: {} }); });
    for (const [index, activeModule] of ['dns', 'network', 'process', 'file', 'dns'].entries()) {
      if (index) {
        const label = activeModule === 'dns' ? 'DNS'
          : activeModule[0].toUpperCase() + activeModule.slice(1);
        await renderer.act(async () => {
          view.root.findAllByType('EuiTab').find((tab) => tab.props.children === label).props.onClick();
        });
      }
      assert.equal(requests.length, index + 1);
      const request = requests[index];
      assert.equal(request.module, activeModule);
      await renderer.act(async () => request.resolve({
        total: 1, page: 1, pageSize: 25, uniqueEntities: 1, uniqueHosts: 1, highlightCount: 0,
        timeline: [], byType: [], byEntity: [], byHost: [], byFacet: [],
        events: [{ id: activeModule, index: 'telemetry', metadata: {}, source: {
          '@timestamp': base.from, 'event.module': `telemetry.${activeModule}`,
          'event.type': `${activeModule}.example`, ...fixtures[activeModule],
        } }],
      }));
      const displayed = JSON.stringify(view.toJSON(), (key, value) => key === 'props' ? undefined : value);
      assert.ok(displayed.includes(`${activeModule}.example`));
      for (const other of Object.keys(fixtures).filter((name) => name !== activeModule)) {
        assert.ok(!displayed.includes(`${other}.example`));
      }
    }
  } finally {
    await renderer.act(async () => { if (unmount) unmount(); });
  }
});
