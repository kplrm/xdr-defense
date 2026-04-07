declare const require: any;

import {
  addCustomYaraRule,
  buildSignedYaraBundle,
  bulkSyncForgeCoreRules,
  deleteCustomYaraRule,
  getSigningReadiness,
  listExistingForgeCoreRulesForSync,
  listYaraRules,
  updateYaraRule,
  validateYaraContent
} from '../lib/yara_index';
import { fetchLatestYaraForgeCoreRelease } from '../lib/yara_forge_release';
import { getYaraForgeSyncState, updateYaraForgeSyncState } from '../lib/upstream_sync_store';
import {
  ingestYaraRolloutStatusReport,
  listYaraRolloutStatus,
  queueYaraRolloutRequest,
  ruleHealthIndexForTimestamp,
  ruleHealthTimestamp
} from '../lib/yara_rollout_status';

const { schema } = require('@osd/config-schema');

interface TestResult {
  queried: boolean;
  lookback_minutes: number;
  total_hits: number;
  simulated_matches: number;
  query_error?: string;
}

type ForgeCoreSyncStatus = 'idle' | 'processing' | 'completed' | 'failed';
type ForgeCoreSyncPhase = 'idle' | 'downloading' | 'validating' | 'rollout' | 'completed' | 'failed';

interface ForgeCoreSyncMetadata {
  status: ForgeCoreSyncStatus;
  phase?: ForgeCoreSyncPhase;
  sync_id?: string;
  started_at?: string;
  completed_at?: string;
  synced_at?: string;
  attempted?: number;
  loaded?: number;
  imported?: number;
  unchanged?: number;
  removed?: number;
  load_failures?: number;
  active_rules_queued?: number;
  release_tag?: string;
  asset_name?: string;
  rollout?: {
    target_agent_commands: number;
    created: number;
    deduplicated: number;
    planned_rules?: number;
    processed_rules?: number;
  };
  message?: string;
  errors?: string[];
}

let forgeCoreSyncMetadata: ForgeCoreSyncMetadata = { status: 'idle' };
let forgeCoreSyncInFlight = false;
let forgeCoreSyncStartedAtMs = 0;

// Maximum time (ms) before a stale in-flight lock is automatically released.
// With bulk operations the sync finishes in seconds; 10 minutes is a safe ceiling.
const FORGE_SYNC_STALE_AFTER_MS = 10 * 60 * 1000;
const YARA_ROLLOUT_CONFIRMATION_TIMEOUT_MS = 20 * 1000;
const YARA_ROLLOUT_CONFIRMATION_POLL_MS = 1000;

interface YaraRolloutConfirmationSummary {
  target_agents: number;
  confirmed_agents: number;
  applied: number;
  partial: number;
  failed: number;
  pending: number;
  timed_out: boolean;
}

function persistedSyncMetadataSnapshot(): ForgeCoreSyncMetadata {
  const persisted = getYaraForgeSyncState();
  if (!persisted.last_attempted_at) {
    return { status: 'idle' };
  }

  const failed = Boolean(persisted.last_error);
  return {
    status: failed ? 'failed' : 'completed',
    phase: failed ? 'failed' : persisted.phase ?? 'completed',
    started_at: persisted.last_attempted_at,
    completed_at: persisted.last_completed_at,
    synced_at: persisted.last_successful_sync_at,
    attempted: persisted.attempted,
    loaded: persisted.loaded,
    imported: persisted.imported,
    unchanged: persisted.unchanged,
    removed: persisted.removed,
    load_failures: persisted.load_failures,
    active_rules_queued: persisted.active_rules_queued,
    release_tag: persisted.release_tag,
    asset_name: persisted.asset_name,
    rollout: persisted.rollout,
    message: failed ? 'Last YARA Forge Core sync failed.' : 'Last YARA Forge Core sync completed.',
    errors: failed && persisted.last_error ? [persisted.last_error] : []
  };
}

function syncMetadataSnapshot(): ForgeCoreSyncMetadata {
  if (forgeCoreSyncMetadata.status === 'idle') {
    return persistedSyncMetadataSnapshot();
  }
  return {
    ...forgeCoreSyncMetadata,
    errors: [...(forgeCoreSyncMetadata.errors ?? [])]
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function countRolloutTargetAgents(client: any, policyId: string): Promise<number> {
  try {
    if (policyId === 'global-default') {
      const response = await client.count({
        index: 'xdr-agents',
        body: { query: { match_all: {} } }
      });
      return Math.max(0, Number(response?.body?.count ?? 0));
    }

    const response = await client.count({
      index: 'xdr-agents',
      body: { query: { term: { policy_id: policyId } } }
    });
    return Math.max(0, Number(response?.body?.count ?? 0));
  } catch {
    return 0;
  }
}

async function summarizeYaraRolloutConfirmation(
  client: any,
  policyId: string,
  bundleVersion: number,
  targetAgents: number
): Promise<YaraRolloutConfirmationSummary> {
  let applied = 0;
  let partial = 0;
  let failed = 0;
  let confirmed = 0;

  try {
    const response = await client.search({
      index: '.xdr-defense-yara-rollout-status',
      size: 10000,
      body: {
        query: {
          bool: {
            must: [
              { term: { policy_id: policyId } },
              { term: { bundle_version: bundleVersion } }
            ]
          }
        },
        _source: ['agent_id', 'state']
      }
    });

    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];
    confirmed = hits.length;
    for (const hit of hits) {
      const state = String(hit?._source?.state ?? '').toLowerCase();
      if (state === 'applied') {
        applied += 1;
      } else if (state === 'partial') {
        partial += 1;
      } else if (state === 'failed') {
        failed += 1;
      }
    }
  } catch {
    confirmed = 0;
  }

  const pending = Math.max(0, targetAgents - confirmed);
  return {
    target_agents: targetAgents,
    confirmed_agents: confirmed,
    applied,
    partial,
    failed,
    pending,
    timed_out: pending > 0
  };
}

async function waitForYaraRolloutConfirmation(
  client: any,
  policyId: string,
  bundleVersion: number
): Promise<YaraRolloutConfirmationSummary> {
  const targetAgents = await countRolloutTargetAgents(client, policyId);
  const deadline = Date.now() + YARA_ROLLOUT_CONFIRMATION_TIMEOUT_MS;

  let latest = await summarizeYaraRolloutConfirmation(client, policyId, bundleVersion, targetAgents);
  while (latest.pending > 0 && Date.now() < deadline) {
    await sleep(YARA_ROLLOUT_CONFIRMATION_POLL_MS);
    latest = await summarizeYaraRolloutConfirmation(client, policyId, bundleVersion, targetAgents);
  }

  if (latest.pending > 0) {
    return { ...latest, timed_out: true };
  }

  return { ...latest, timed_out: false };
}

async function simulateAgainstRecentDocs(
  ctx: any,
  sampleText: string,
  lookbackMinutes: number
): Promise<TestResult> {
  try {
    const scopedClient =
      typeof ctx?.core?.opensearch?.client?.asCurrentUser?.search === 'function'
        ? ctx.core.opensearch.client.asCurrentUser
        : typeof ctx?.opensearch?.client?.asCurrentUser?.search === 'function'
          ? ctx.opensearch.client.asCurrentUser
          : null;

    if (!scopedClient) {
      return {
        queried: false,
        lookback_minutes: lookbackMinutes,
        total_hits: 0,
        simulated_matches: 0,
        query_error: 'OpenSearch scoped client unavailable in route context.'
      };
    }

    const response = await scopedClient.search({
      index: '*',
      size: 50,
      track_total_hits: true,
      body: {
        query: {
          range: {
            '@timestamp': {
              gte: `now-${lookbackMinutes}m`
            }
          }
        },
        _source: ['message', 'process.command_line', 'file.path', 'event.original']
      }
    });

    const totalHitsRaw = response?.body?.hits?.total;
    const totalHits =
      typeof totalHitsRaw?.value === 'number'
        ? totalHitsRaw.value
        : typeof totalHitsRaw === 'number'
          ? totalHitsRaw
          : 0;

    const sample = sampleText.trim().toLowerCase();
    const hits = Array.isArray(response?.body?.hits?.hits) ? response.body.hits.hits : [];

    let simulatedMatches = 0;
    if (sample.length > 0) {
      for (const hit of hits) {
        const source = hit?._source ?? {};
        const values = [
          source.message,
          source['event.original'],
          source?.process?.command_line,
          source?.file?.path
        ]
          .filter((entry: unknown) => typeof entry === 'string')
          .map((entry: unknown) => String(entry).toLowerCase());

        if (values.some((value) => value.includes(sample))) {
          simulatedMatches += 1;
        }
      }
    }

    return {
      queried: true,
      lookback_minutes: lookbackMinutes,
      total_hits: totalHits,
      simulated_matches: simulatedMatches
    };
  } catch (err: any) {
    return {
      queried: false,
      lookback_minutes: lookbackMinutes,
      total_hits: 0,
      simulated_matches: 0,
      query_error: `Simulation query failed: ${String(err?.message ?? err)}`
    };
  }
}

function scopedOsClient(ctx: any): any | null {
  if (typeof ctx?.core?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.core.opensearch.client.asCurrentUser;
  }
  if (typeof ctx?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.opensearch.client.asCurrentUser;
  }
  return null;
}

// ACK validation schema (shared between current and legacy routes)
const ackValidationSchema = {
  body: schema.object({
    command_id: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
    command_key: schema.maybe(schema.string({ minLength: 1, maxLength: 512 })),
    agent_id: schema.string({ minLength: 1, maxLength: 256 }),
    rule_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
    action: schema.maybe(schema.oneOf([schema.literal('activate'), schema.literal('deactivate'), schema.literal('delete')])),
    dispatch_version: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
    status: schema.oneOf([schema.literal('acknowledged'), schema.literal('failed')]),
    reason: schema.maybe(schema.string({ minLength: 1, maxLength: 2048 }))
  })
};

// Rule-status validation schema (shared between current and legacy routes)
const rolloutStatusValidationSchema = {
  body: schema.object({
    manager_policy_id: schema.string({ minLength: 1, maxLength: 256 }),
    agent_id: schema.string({ minLength: 1, maxLength: 256 }),
    state: schema.oneOf([schema.literal('acked'), schema.literal('partial'), schema.literal('failed')]),
    total_rules: schema.number({ min: 0 }),
    loaded_rules: schema.number({ min: 0 }),
    failed_rules: schema.arrayOf(
      schema.object({
        rule_id: schema.string({ minLength: 1, maxLength: 512 }),
        status: schema.string({ minLength: 1, maxLength: 64 }),
        error_message: schema.maybe(schema.string({ minLength: 1, maxLength: 4096 })),
        loaded_at: schema.maybe(schema.number({ min: 0 }))
      }),
      { defaultValue: [] }
    ),
    reported_at: schema.number({ min: 0 })
  })
};

const inventoryValidationSchema = {
  body: schema.object({
    agent_id: schema.string({ minLength: 1, maxLength: 256 }),
    loaded_rule_count: schema.number({ min: 0 }),
    failed_rules: schema.arrayOf(schema.object({}, { unknowns: 'allow' }), { defaultValue: [] }),
    checked_at: schema.oneOf([
      schema.number({ min: 0 }),
      schema.string({ minLength: 1, maxLength: 128 })
    ])
  })
};

// Handler functions for rollout endpoints (shared between current and legacy routes)
async function handleRolloutStatus(ctx: any, res: any) {
  try {
    const client = scopedOsClient(ctx);
    if (!client) {
      return res.customError({
        statusCode: 503,
        body: { message: 'OpenSearch scoped client unavailable.' }
      });
    }

    const status = await listYaraRolloutStatus(client, { page: 1, pageSize: 100 });
    return res.ok({ body: status });
  } catch (err: any) {
    return res.customError({
      statusCode: 500,
      body: {
        message: 'Failed to load rollout status.',
        details: String(err?.message ?? err)
      }
    });
  }
}

async function handleRolloutRetry(ctx: any, res: any) {
  try {
    const client = scopedOsClient(ctx);
    if (!client) {
      return res.customError({
        statusCode: 503,
        body: { message: 'OpenSearch scoped client unavailable.' }
      });
    }
    const policyId = 'global-default';
    const bundleResult = await buildSignedYaraBundle(client, policyId);
    if (!bundleResult.bundle) {
      return res.customError({
        statusCode: 409,
        body: {
          message: 'No cached YARA bundle is available to retry.',
          details: bundleResult.error ?? 'Build cached bundle first.'
        }
      });
    }

    const request = await queueYaraRolloutRequest(client, {
      policy_id: policyId,
      bundle_version: bundleResult.bundle.bundle_version,
      generated_at: bundleResult.bundle.generated_at,
      requested_at: new Date().toISOString(),
      rule_count: bundleResult.bundle.rules.length
    });
    const confirmation = await waitForYaraRolloutConfirmation(client, policyId, request.bundle_version);
    const status = await listYaraRolloutStatus(client, { page: 1, pageSize: 100 });
    return res.ok({
      body: {
        retried: 1,
        bundle_version: request.bundle_version,
        confirmation,
        status
      }
    });
  } catch (err: any) {
    return res.customError({
      statusCode: 500,
      body: {
        message: 'Failed to retry rollout failures.',
        details: String(err?.message ?? err)
      }
    });
  }
}

async function handleRolloutAck(ctx: any, req: any, res: any) {
  return res.ok({ body: { acknowledged: true, legacy: true, request: req.body ?? {} } });
}

async function handleRolloutStatusIngestion(ctx: any, req: any, res: any) {
  try {
    const client = scopedOsClient(ctx);
    if (!client) {
      return res.customError({
        statusCode: 503,
        body: { message: 'OpenSearch scoped client unavailable.' }
      });
    }

    const ingestion = await ingestYaraRolloutStatusReport(client, req.body ?? {});
    return res.ok({ body: ingestion });
  } catch (err: any) {
    return res.customError({
      statusCode: 500,
      body: {
        message: 'Failed to ingest rollout status report.',
        details: String(err?.message ?? err)
      }
    });
  }
}

export function registerYaraRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr-defense/yara/rules',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        const client = scopedOsClient(_ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch scoped client unavailable.' }
          });
        }
        const rules = await listYaraRules(client);
        return res.ok({ body: { rules } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to list YARA rules.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/rules',
      validate: {
        body: schema.object({
          name: schema.string({ minLength: 1, maxLength: 160 }),
          content: schema.string({ minLength: 1, maxLength: 200000 }),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }
        const created = await addCustomYaraRule(client, req.body ?? {});
        const statusCode = created.validation.status === 'valid' ? 200 : 400;
        if (statusCode === 400) {
          return res.customError({
            statusCode,
            body: {
              message: 'YARA rule validation failed.',
              rule: created,
              validation: created.validation
            }
          });
        }
        return res.ok({ body: { ...created } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to create YARA rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/yara/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) }),
        body: schema.object({
          enabled: schema.maybe(schema.boolean()),
          content: schema.maybe(schema.string({ minLength: 1, maxLength: 200000 })),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 })),
          name: schema.maybe(schema.string({ minLength: 1, maxLength: 160 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }
        const { id } = req.params;
        const result = await updateYaraRule(client, id, req.body ?? {});
        if (!result.updated) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({
            statusCode: code,
            body: {
              message: result.error ?? 'Failed to update YARA rule.'
            }
          });
        }
        return res.ok({ body: { ...result.updated } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to update YARA rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.delete(
    {
      path: '/api/xdr-defense/yara/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }
        const result = await deleteCustomYaraRule(client, req.params.id);
        if (!result.deleted) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({
            statusCode: code,
            body: {
              message: result.error ?? 'Failed to delete YARA rule.'
            }
          });
        }
        return res.ok({ body: { deleted: true, id: req.params.id } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to delete YARA rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/test',
      validate: {
        body: schema.object({
          content: schema.string({ minLength: 1, maxLength: 200000 }),
          sample_text: schema.maybe(schema.string({ minLength: 0, maxLength: 4096 })),
          lookback_minutes: schema.maybe(schema.number({ min: 1, max: 10080 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const lookbackMinutes = Number(req.body?.lookback_minutes ?? 60);
        const validation = validateYaraContent(req.body?.content ?? '');
        const simulation = await simulateAgainstRecentDocs(ctx, String(req.body?.sample_text ?? ''), lookbackMinutes);

        return res.ok({
          body: {
            validation,
            simulation
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to execute YARA test.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara/bundle',
      options: {
        authRequired: false
      },
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }
        const policyId = String(req.query?.policy_id ?? 'global-default');
        const readiness = getSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed bundle generation unavailable.',
              details: readiness.reason
            }
          });
        }

        const result = await buildSignedYaraBundle(client, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed bundle generation unavailable.',
              details: result.error ?? 'Failed to sign bundle.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build YARA bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/forge-core/sync',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => {
      // Auto-release a stale lock if the previous sync has been in-flight for too long.
      if (forgeCoreSyncInFlight && Date.now() - forgeCoreSyncStartedAtMs > FORGE_SYNC_STALE_AFTER_MS) {
        forgeCoreSyncInFlight = false;
        forgeCoreSyncStartedAtMs = 0;
      }

      if (forgeCoreSyncInFlight) {
        const snapshot = syncMetadataSnapshot();
        return res.ok({
          body: {
            status: 'running',
            started: false,
            sync_id: forgeCoreSyncMetadata.sync_id,
            parallel_workers: 0,
            attempted: snapshot.attempted ?? 0,
            loaded: snapshot.loaded ?? 0,
            imported: snapshot.imported ?? 0,
            unchanged: snapshot.unchanged ?? 0,
            active_rules_queued: snapshot.active_rules_queued ?? 0,
            load_failures: snapshot.load_failures ?? 0,
            rollout: {
              target_agent_commands: snapshot.rollout?.target_agent_commands ?? 0,
              created: snapshot.rollout?.created ?? 0,
              deduplicated: snapshot.rollout?.deduplicated ?? 0,
              planned_rules: snapshot.rollout?.planned_rules ?? 0,
              processed_rules: snapshot.rollout?.processed_rules ?? 0
            },
            errors: snapshot.errors ?? [],
            metadata: snapshot
          }
        });
      }

      const startedAt = new Date().toISOString();
      const syncId = `forge-core-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      forgeCoreSyncInFlight = true;
      forgeCoreSyncStartedAtMs = Date.now();
      forgeCoreSyncMetadata = {
        status: 'processing',
        phase: 'downloading',
        sync_id: syncId,
        started_at: startedAt,
        message: 'YARA Forge Core sync started.',
        errors: []
      };
      updateYaraForgeSyncState({
        phase: 'downloading',
        last_attempted_at: startedAt,
        last_error: undefined,
        rollout: {
          target_agent_commands: 0,
          created: 0,
          deduplicated: 0,
          planned_rules: 0,
          processed_rules: 0
        }
      });

      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          throw new Error('OpenSearch scoped client unavailable.');
        }

        const release = await fetchLatestYaraForgeCoreRelease();

        forgeCoreSyncMetadata = {
          ...forgeCoreSyncMetadata,
          phase: 'validating',
          release_tag: release.release_tag,
          asset_name: release.asset_name,
          attempted: release.sources.length,
          loaded: release.sources.length,
          imported: 0,
          unchanged: 0,
          removed: 0,
          load_failures: 0,
          active_rules_queued: 0,
          rollout: {
            target_agent_commands: 0,
            created: 0,
            deduplicated: 0,
            planned_rules: 0,
            processed_rules: 0
          },
          message: 'Validating YARA Forge Core rules before rollout.'
        };
        updateYaraForgeSyncState({
          phase: 'validating',
          release_tag: release.release_tag,
          asset_name: release.asset_name,
          asset_updated_at: release.asset_updated_at,
          attempted: release.sources.length,
          loaded: release.sources.length,
          imported: 0,
          unchanged: 0,
          removed: 0,
          load_failures: 0,
          active_rules_queued: 0,
          rollout: {
            target_agent_commands: 0,
            created: 0,
            deduplicated: 0,
            planned_rules: 0,
            processed_rules: 0
          }
        });

        // Keep validating observable to polling clients even when processing is fast.
        await sleep(900);

        let imported = 0;
        let unchanged = 0;
        let removed = 0;
        let activeRulesQueued = 0;
        let totalDispatchTargets = 0;
        let totalDispatchCreated = 0;
        let totalDispatchDeduplicated = 0;
        let processedRolloutRules = 0;
        const importErrors: string[] = [];

        // Fetch all existing forge-core rule states in one search query
        // (avoids 5000+ individual GET calls that caused the sync to appear stuck).
        const existingForgeCoreMap = await listExistingForgeCoreRulesForSync(client);
        const seenRuleIds = new Set(release.sources.map((s) => String(s.id)));

        // Bulk-sync: compare in memory, write changes in one bulk operation.
        const syncResult = await bulkSyncForgeCoreRules(client, release.sources, existingForgeCoreMap);
        imported = syncResult.imported;
        unchanged = syncResult.unchanged;
        activeRulesQueued = syncResult.activeRulesQueued;

        // Remove forge-core rules that are no longer present in the upstream release.
        for (const existingId of existingForgeCoreMap.keys()) {
          if (!seenRuleIds.has(existingId)) {
            const deleted = await deleteCustomYaraRule(client, existingId);
            if (deleted.deleted) {
              removed += 1;
            } else {
              importErrors.push(`${existingId}: failed to remove stale Forge rule.`);
            }
          }
        }

        const policyId = 'global-default';
        const bundleResult = await buildSignedYaraBundle(client, policyId);
        if (!bundleResult.bundle) {
          throw new Error(bundleResult.error ?? 'Failed to build cached YARA bundle.');
        }

        const agentCountResponse = await client.count({
          index: 'xdr-agents',
          body: { query: { term: { policy_id: policyId } } }
        }).catch(() => ({ body: { count: 0 } }));
        const targetAgentCount = Number(agentCountResponse?.body?.count ?? 0);

        const request = await queueYaraRolloutRequest(client, {
          policy_id: policyId,
          bundle_version: bundleResult.bundle.bundle_version,
          generated_at: bundleResult.bundle.generated_at,
          requested_at: new Date().toISOString(),
          rule_count: bundleResult.bundle.rules.length
        });

        const plannedRolloutRules = bundleResult.bundle.rules.length;

        forgeCoreSyncMetadata = {
          ...forgeCoreSyncMetadata,
          phase: 'rollout',
          attempted: release.sources.length,
          loaded: release.sources.length,
          imported,
          unchanged,
          removed,
          load_failures: 0,
          active_rules_queued: activeRulesQueued,
          rollout: {
            target_agent_commands: targetAgentCount,
            created: targetAgentCount,
            deduplicated: 0,
            planned_rules: plannedRolloutRules,
            processed_rules: plannedRolloutRules
          },
          message: 'Verified rules, built cached bundle, and queued agent rollout.'
        };
        updateYaraForgeSyncState({
          phase: 'rollout',
          attempted: release.sources.length,
          loaded: release.sources.length,
          imported,
          unchanged,
          removed,
          load_failures: 0,
          active_rules_queued: activeRulesQueued,
          rollout: {
            target_agent_commands: targetAgentCount,
            created: targetAgentCount,
            deduplicated: 0,
            planned_rules: plannedRolloutRules,
            processed_rules: plannedRolloutRules
          }
        });
        totalDispatchTargets = targetAgentCount;
        totalDispatchCreated = targetAgentCount;
        totalDispatchDeduplicated = 0;
        processedRolloutRules = plannedRolloutRules;

        const completedAt = new Date().toISOString();
        updateYaraForgeSyncState({
          phase: 'completed',
          release_tag: release.release_tag,
          asset_name: release.asset_name,
          asset_updated_at: release.asset_updated_at,
          last_attempted_at: startedAt,
          last_completed_at: completedAt,
          last_successful_sync_at: completedAt,
          attempted: release.sources.length,
          loaded: release.sources.length,
          imported,
          unchanged,
          removed,
          load_failures: 0,
          active_rules_queued: activeRulesQueued,
          rollout: {
            target_agent_commands: request.bundle_version > 0 ? totalDispatchTargets : 0,
            created: request.bundle_version > 0 ? totalDispatchCreated : 0,
            deduplicated: totalDispatchDeduplicated,
            planned_rules: plannedRolloutRules,
            processed_rules: processedRolloutRules
          },
          last_error: undefined
        });
        forgeCoreSyncMetadata = {
          status: 'completed',
          phase: 'completed',
          sync_id: syncId,
          started_at: startedAt,
          completed_at: completedAt,
          synced_at: completedAt,
          attempted: release.sources.length,
          loaded: release.sources.length,
          imported,
          unchanged,
          removed,
          load_failures: 0,
          active_rules_queued: activeRulesQueued,
          release_tag: release.release_tag,
          asset_name: release.asset_name,
          rollout: {
            target_agent_commands: totalDispatchTargets,
            created: totalDispatchCreated,
            deduplicated: totalDispatchDeduplicated,
            planned_rules: plannedRolloutRules,
            processed_rules: processedRolloutRules
          },
          message: `YARA Forge Core sync completed. Cached bundle v${request.bundle_version} queued for rollout.`,
          errors: importErrors.sort((a, b) => a.localeCompare(b))
        };

        return res.ok({
          body: {
            status: 'completed',
            started: true,
            sync_id: syncId,
            message: 'YARA Forge Core sync completed.',
            parallel_workers: 1,
            attempted: release.sources.length,
            loaded: release.sources.length,
            load_failures: 0,
            imported,
            unchanged,
            removed,
            active_rules_queued: activeRulesQueued,
            release_tag: release.release_tag,
            asset_name: release.asset_name,
            bundle_version: request.bundle_version,
            rollout: {
              target_agent_commands: totalDispatchTargets,
              created: totalDispatchCreated,
              deduplicated: totalDispatchDeduplicated,
              planned_rules: plannedRolloutRules,
              processed_rules: processedRolloutRules
            },
            errors: importErrors.sort((a, b) => a.localeCompare(b)),
            metadata: syncMetadataSnapshot()
          }
        });
      } catch (err: any) {
        updateYaraForgeSyncState({
          phase: 'failed',
          last_attempted_at: startedAt,
          last_completed_at: new Date().toISOString(),
          last_error: String(err?.message ?? err)
        });
        forgeCoreSyncMetadata = {
          status: 'failed',
          phase: 'failed',
          sync_id: syncId,
          started_at: startedAt,
          completed_at: new Date().toISOString(),
          message: 'Failed to sync YARA Forge Core.',
          errors: [String(err?.message ?? err)]
        };
        return res.customError({
          statusCode: 502,
          body: {
            message: 'Failed to sync YARA Forge Core.',
            details: String(err?.message ?? err)
          }
        });
      } finally {
        forgeCoreSyncInFlight = false;
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara/forge-core/status',
      validate: false
    },
    async (_ctx: any, _req: any, res: any) => {
      return res.ok({ body: syncMetadataSnapshot() });
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara/rollouts/status',
      validate: {
        query: schema.object({
          page: schema.maybe(schema.number({ min: 1, max: 100000 })),
          pageSize: schema.maybe(schema.number({ min: 1, max: 500 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }
        const status = await listYaraRolloutStatus(client, {
          page: req.query?.page,
          pageSize: req.query?.pageSize
        });
        return res.ok({ body: status });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to load rollout status.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  // Legacy alias: /api/xdr-defense/yara-rollouts/status
  router.get(
    {
      path: '/api/xdr-defense/yara-rollouts/status',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => handleRolloutStatus(ctx, res)
  );

  // Current endpoint: POST /api/xdr-defense/yara/rollouts/status
  router.post(
    {
      path: '/api/xdr-defense/yara/rollouts/status',
      options: {
        authRequired: false
      },
      validate: {
        body: schema.object({
          manager_policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
          agent_id: schema.string({ minLength: 1, maxLength: 256 }),
          agent_hostname: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
          state: schema.string({ minLength: 1, maxLength: 64 }),
          bundle_version: schema.maybe(schema.number({ min: 0 })),
          total_rules: schema.maybe(schema.number({ min: 0 })),
          loaded_rules: schema.maybe(schema.number({ min: 0 })),
          failed_rules: schema.maybe(schema.arrayOf(schema.object({}, { unknowns: 'allow' }), { defaultValue: [] })),
          reported_at: schema.maybe(schema.oneOf([schema.number({ min: 0 }), schema.string({ minLength: 1, maxLength: 128 })]))
        })
      }
    },
    async (ctx: any, req: any, res: any) => handleRolloutStatusIngestion(ctx, req, res)
  );

  // Legacy alias: POST /api/xdr-defense/yara-rollouts/status
  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/status',
      options: {
        authRequired: false
      },
      validate: rolloutStatusValidationSchema
    },
    async (ctx: any, req: any, res: any) => handleRolloutStatusIngestion(ctx, req, res)
  );

  // Current endpoint: /api/xdr-defense/yara/rollouts/retry
  router.post(
    {
      path: '/api/xdr-defense/yara/rollouts/retry',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => handleRolloutRetry(ctx, res)
  );

  // Legacy alias: /api/xdr-defense/yara-rollouts/retry
  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/retry',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => handleRolloutRetry(ctx, res)
  );

  // Current endpoint: /api/xdr-defense/yara/rollouts/ack
  router.post(
    {
      path: '/api/xdr-defense/yara/rollouts/ack',
      options: {
        authRequired: false
      },
      validate: ackValidationSchema
    },
    async (ctx: any, req: any, res: any) => handleRolloutAck(ctx, req, res)
  );

  // Legacy alias: /api/xdr-defense/yara-rollouts/ack
  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/ack',
      options: {
        authRequired: false
      },
      validate: ackValidationSchema
    },
    async (ctx: any, req: any, res: any) => handleRolloutAck(ctx, req, res)
  );

  // POST /api/xdr-defense/yara-rules/inventory/query
  // Query latest rule inventory for a specific agent
  router.post(
    {
      path: '/api/xdr-defense/yara-rules/inventory/query',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 })
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const scopedClient = ctx?.core?.opensearch?.client?.asCurrentUser ?? ctx?.opensearch?.client?.asCurrentUser;
        if (!scopedClient) {
          return res.customError({
            statusCode: 500,
            body: { message: 'OpenSearch client unavailable.' }
          });
        }

        const { agent_id } = req.body;

        // Query the latest rule health document for this agent
        const searchResponse = await scopedClient.search({
          index: '.xdr-defense-rule-health-*',
          size: 1,
          sort: [{ '@timestamp': { order: 'desc' } }],
          query: {
            match: { agent_id }
          }
        });

        const hit = searchResponse?.body?.hits?.hits?.[0];
        if (hit) {
          const inventory = hit._source;
          return res.ok({
            body: { 
              inventory,
              timestamp: new Date().toISOString()
            }
          });
        }

        return res.ok({
          body: {
            inventory: null,
            message: 'No rule inventory data found for agent.'
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to query rule inventory.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara-rules/inventory',
      options: {
        authRequired: false
      },
      validate: inventoryValidationSchema
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch scoped client unavailable.' }
          });
        }

        const checkedAtIso = ruleHealthTimestamp(req.body?.checked_at);
        const targetIndex = ruleHealthIndexForTimestamp(req.body?.checked_at);
        const failedRules = Array.isArray(req.body?.failed_rules) ? req.body.failed_rules : [];

        await client.index({
          index: targetIndex,
          refresh: 'wait_for',
          body: {
            '@timestamp': checkedAtIso,
            kind: 'yara_rule_inventory',
            agent_id: req.body.agent_id,
            loaded_rule_count: req.body.loaded_rule_count,
            failed_rules: failedRules,
            failed_rule_count: failedRules.length,
            checked_at: req.body.checked_at,
            ingest_time: new Date().toISOString()
          }
        });

        return res.ok({
          body: {
            accepted: true,
            stored_index: targetIndex,
            failed_rule_count: failedRules.length
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to ingest YARA rule inventory.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/bundle/build',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }
        const policyId = String(req.body?.policy_id ?? 'global-default');
        const readiness = getSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Bundle signing unavailable.',
              details: readiness.reason
            }
          });
        }

        const result = await buildSignedYaraBundle(client, policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Bundle generation failed.',
              details: result.error ?? 'Unknown error.'
            }
          });
        }

        return res.ok({
          body: {
            message: 'Bundle built and signed successfully.',
            bundle: result.bundle
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build YARA bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/rollout',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedOsClient(ctx);
        if (!client) {
          return res.customError({ statusCode: 503, body: { message: 'OpenSearch scoped client unavailable.' } });
        }

        const policyId = String(req.body?.policy_id ?? 'global-default');
        const bundleResult = await buildSignedYaraBundle(client, policyId);
        if (!bundleResult.bundle) {
          return res.customError({
            statusCode: 409,
            body: {
              started: false,
              success: false,
              message: 'No cached YARA bundle available.',
              details: bundleResult.error ?? 'Build the cached bundle first.',
              policy_id: policyId
            }
          });
        }

        const request = await queueYaraRolloutRequest(client, {
          policy_id: policyId,
          bundle_version: bundleResult.bundle.bundle_version,
          generated_at: bundleResult.bundle.generated_at,
          requested_at: new Date().toISOString(),
          rule_count: bundleResult.bundle.rules.length
        });
        const confirmation = await waitForYaraRolloutConfirmation(client, policyId, request.bundle_version);

        return res.ok({
          body: {
            started: true,
            success: true,
            message: confirmation.timed_out
              ? 'Cached YARA bundle rollout requested. Waiting for some agents to confirm timed out; check YARA Rollout Status.'
              : 'Cached YARA bundle rollout confirmed by all targeted agents.',
            policy_id: policyId,
            bundle_version: request.bundle_version,
            generated_at: request.generated_at,
            rule_count: request.rule_count,
            confirmation
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to roll out YARA bundle to agents.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );
}
