import type { Logger } from '../../../../src/core/server';

const INDEX_TEMPLATES = [
  {
    name: 'xdr-alerts-template',
    body: {
      index_patterns: ['xdr-alerts-*'],
      template: {
        settings: { number_of_shards: 1 },
        mappings: {
          dynamic: true,
          properties: {
            '@timestamp': { type: 'date' },
            'event.type': { type: 'keyword' },
            'event.module': { type: 'keyword' },
            'event.severity': { type: 'integer' },
            'rule.id': { type: 'keyword' },
            'rule.name': { type: 'keyword' },
            'threat.tactic.name': { type: 'keyword' },
            'threat.technique.id': { type: 'keyword' },
          },
        },
      },
      priority: 500,
      version: 1,
      _meta: { owner: 'xdr-defense' },
    },
  },
  {
    name: 'xdr-prevention-actions-template',
    body: {
      index_patterns: ['xdr-prevention-actions-*'],
      template: {
        settings: { number_of_shards: 1 },
        mappings: {
          dynamic: true,
          properties: {
            '@timestamp': { type: 'date' },
            'event.type': { type: 'keyword' },
            'event.module': { type: 'keyword' },
            action: { type: 'keyword' },
            source_rule_id: { type: 'keyword' },
            source_module: { type: 'keyword' },
            'agent.id': { type: 'keyword' },
            'host.hostname': { type: 'keyword' },
          },
        },
      },
      priority: 500,
      version: 1,
      _meta: { owner: 'xdr-defense' },
    },
  },
  {
    name: 'xdr-agent-logs-template',
    body: {
      index_patterns: ['xdr-agent-logs-*'],
      template: {
        settings: { number_of_shards: 1 },
        mappings: {
          dynamic: true,
          properties: {
            '@timestamp': { type: 'date' },
            'log.level': { type: 'keyword' },
            message: { type: 'text' },
            'event.module': { type: 'keyword' },
            'agent.id': { type: 'keyword' },
            'host.hostname': { type: 'keyword' },
          },
        },
      },
      priority: 500,
      version: 1,
      _meta: { owner: 'xdr-defense' },
    },
  },
];

const INGEST_PIPELINES = [
  {
    id: 'xdr-alerts-pipeline',
    body: {
      description: 'Normalize xdr alert fields and add ingest metadata',
      processors: [
        { set: { field: 'event.dataset', value: 'xdr.alerts' } },
        { set: { field: 'labels.ingested_by', value: 'xdr-defense' } },
      ],
    },
  },
  {
    id: 'xdr-agent-logs-pipeline',
    body: {
      description: 'Normalize xdr agent logs',
      processors: [
        { set: { field: 'event.dataset', value: 'xdr.agent_logs' } },
        {
          rename: {
            field: 'payload.log.level',
            target_field: 'log.level',
            ignore_missing: true,
          },
        },
        {
          rename: {
            field: 'payload.message',
            target_field: 'message',
            ignore_missing: true,
          },
        },
      ],
    },
  },
];

const CORRELATION_RULES = [
  {
    id: 'bruteforce-window-rule',
    name: 'xdr-bruteforce-window',
    source: {
      name: 'xdr-bruteforce-window',
      type: 'query',
      schedule: { interval: { period: 1, unit: 'MINUTES' } },
      inputs: [
        {
          search: {
            indices: ['xdr-alerts-*'],
            query: {
              size: 0,
              query: {
                bool: {
                  filter: [
                    { range: { '@timestamp': { gte: 'now-5m' } } },
                    { term: { 'rule.id': 'credential.bruteforce.failed_logins' } },
                  ],
                },
              },
            },
          },
        },
      ],
      triggers: [{ name: 'bruteforce-threshold', severity: '2', condition: { script: { source: 'return true;' } }, actions: [] }],
    },
  },
  {
    id: 'ransomware-burst-rule',
    name: 'xdr-ransomware-burst',
    source: {
      name: 'xdr-ransomware-burst',
      type: 'query',
      schedule: { interval: { period: 1, unit: 'MINUTES' } },
      inputs: [
        {
          search: {
            indices: ['xdr-alerts-*'],
            query: {
              size: 0,
              query: {
                bool: {
                  filter: [
                    { range: { '@timestamp': { gte: 'now-3m' } } },
                    { wildcard: { 'rule.id': 'ransomware.*' } },
                  ],
                },
              },
            },
          },
        },
      ],
      triggers: [{ name: 'ransomware-burst-threshold', severity: '1', condition: { script: { source: 'return true;' } }, actions: [] }],
    },
  },
];

export async function installManagedAssets(client: any, logger: Logger) {
  for (const template of INDEX_TEMPLATES) {
    try {
      await client.indices.putIndexTemplate({
        name: template.name,
        body: template.body,
      });
      logger.info(`xdr_defense: installed index template ${template.name}`);
    } catch (err: any) {
      logger.warn(`xdr_defense: failed installing index template ${template.name}: ${err?.message ?? err}`);
    }
  }

  for (const pipeline of INGEST_PIPELINES) {
    try {
      await client.ingest.putPipeline({
        id: pipeline.id,
        body: pipeline.body,
      });
      logger.info(`xdr_defense: installed ingest pipeline ${pipeline.id}`);
    } catch (err: any) {
      logger.warn(`xdr_defense: failed installing ingest pipeline ${pipeline.id}: ${err?.message ?? err}`);
    }
  }
}

export function listCorrelationRuleAssets() {
  return CORRELATION_RULES;
}
