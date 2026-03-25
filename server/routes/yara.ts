declare const require: any;

import {
  addCustomYaraRule,
  buildSignedYaraBundle,
  deleteCustomYaraRule,
  getExistingForgeCoreRuleState,
  getSigningReadiness,
  getYaraRule,
  listYaraRules,
  upsertForgeCoreYaraRule,
  updateYaraRule,
  validateYaraContent
} from '../lib/yara_store';
import { fetchLatestYaraForgeCoreRelease } from '../lib/yara_forge_release';
import { getYaraForgeSyncState, updateYaraForgeSyncState } from '../lib/upstream_sync_store';
import {
  acknowledgeRollout,
  dispatchRolloutForAgents,
  ingestYaraRolloutStatusReport,
  listEnrolledAgents,
  listRolloutStatus,
  retryRetryableCommands
} from '../lib/yara_rollout';

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

async function dispatchRuleRollout(ctx: any, rule: { id: string; name: string; updatedAt: string }, action: 'activate' | 'deactivate' | 'delete') {
  const client = scopedOsClient(ctx);
  if (!client) {
    return {
      queued: false,
      reason: 'OpenSearch scoped client unavailable for rollout dispatch.'
    };
  }

  const agents = await listEnrolledAgents(client);
  const dispatch = await dispatchRolloutForAgents(client, agents, rule, action);
  return {
    queued: true,
    action,
    agents: agents.length,
    dispatched: dispatch.dispatched,
    deduplicated: dispatch.deduplicated
  };
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

    const status = await listRolloutStatus(client);
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
    const result = await retryRetryableCommands(client);
    const status = await listRolloutStatus(client);
    return res.ok({
      body: {
        retried: result.retried,
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
  try {
    const client = scopedOsClient(ctx);
    if (!client) {
      return res.customError({
        statusCode: 503,
        body: { message: 'OpenSearch scoped client unavailable.' }
      });
    }

    const ackResult = await acknowledgeRollout(client, req.body ?? {});
    if (!ackResult.updated) {
      return res.customError({
        statusCode: 404,
        body: {
          message: ackResult.reason ?? 'Rollout command not found for ACK.'
        }
      });
    }

    return res.ok({ body: { acknowledged: true } });
  } catch (err: any) {
    return res.customError({
      statusCode: 500,
      body: {
        message: 'Failed to acknowledge rollout command.',
        details: String(err?.message ?? err)
      }
    });
  }
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
        const rules = listYaraRules();
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
        const created = addCustomYaraRule(req.body ?? {});
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
        const rollout = created.enabled
          ? await dispatchRuleRollout(ctx, { id: created.id, name: created.name, updatedAt: created.updatedAt }, 'activate')
          : { queued: false, reason: 'Rule is disabled due to validation state.' };
        return res.ok({ body: { ...created, rollout } });
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
        const { id } = req.params;
        const previous = getYaraRule(id);
        const result = updateYaraRule(id, req.body ?? {});
        if (!result.updated) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({
            statusCode: code,
            body: {
              message: result.error ?? 'Failed to update YARA rule.'
            }
          });
        }

        let rollout: any = { queued: false, reason: 'No rollout action required.' };
        if (previous && previous.enabled !== result.updated.enabled) {
          rollout = await dispatchRuleRollout(
            ctx,
            { id: result.updated.id, name: result.updated.name, updatedAt: result.updated.updatedAt },
            result.updated.enabled ? 'activate' : 'deactivate'
          );
        } else if (result.updated.enabled) {
          // Keep active rule content aligned on agents when content/severity/tags change.
          rollout = await dispatchRuleRollout(
            ctx,
            { id: result.updated.id, name: result.updated.name, updatedAt: result.updated.updatedAt },
            'activate'
          );
        }

        return res.ok({ body: { ...result.updated, rollout } });
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
        const target = getYaraRule(req.params.id);
        const result = deleteCustomYaraRule(req.params.id);
        if (!result.deleted) {
          const code = result.error === 'Rule not found.' ? 404 : 400;
          return res.customError({
            statusCode: code,
            body: {
              message: result.error ?? 'Failed to delete YARA rule.'
            }
          });
        }

        const rollout = target
          ? await dispatchRuleRollout(ctx, { id: target.id, name: target.name, updatedAt: target.updatedAt }, 'delete')
          : { queued: false, reason: 'Deleted rule was not found for rollout dispatch.' };

        return res.ok({ body: { deleted: true, id: req.params.id, rollout } });
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
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
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

        const result = buildSignedYaraBundle(policyId);
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

        const seenRuleIds = new Set<string>();
        const rolloutCandidates: Array<{ id: string; name: string; updatedAt: string; action: 'activate' | 'deactivate' | 'delete' }> = [];
        for (const source of release.sources) {
          seenRuleIds.add(source.id);
          const existingState = getExistingForgeCoreRuleState(source.id);
          const upserted = upsertForgeCoreYaraRule({
            id: source.id,
            name: source.name,
            content: source.content,
            severity: source.severity,
            tags: source.tags,
            enabled: existingState ? existingState.enabled : true
          });

          if (!upserted.changed) {
            unchanged += 1;
          } else {
            imported += 1;
          }

          if (upserted.rule.enabled) {
            activeRulesQueued += 1;
          }

          // Pre-filter rollout to only changed/new rules; unchanged rules are skipped.
          if (upserted.changed) {
            if (upserted.rule.enabled) {
              rolloutCandidates.push({
                id: upserted.rule.id,
                name: upserted.rule.name,
                updatedAt: upserted.rule.updatedAt,
                action: 'activate'
              });
            } else if (existingState?.enabled) {
              rolloutCandidates.push({
                id: upserted.rule.id,
                name: upserted.rule.name,
                updatedAt: upserted.rule.updatedAt,
                action: 'deactivate'
              });
            }
          }
        }

        const existingForgeRules = listYaraRules().filter((rule) => rule.source === 'forge-core');
        for (const existingRule of existingForgeRules) {
          if (seenRuleIds.has(existingRule.id)) {
            continue;
          }

          const target = getYaraRule(existingRule.id);
          const deleted = deleteCustomYaraRule(existingRule.id);
          if (!deleted.deleted) {
            importErrors.push(`${existingRule.id}: failed to remove stale Forge rule.`);
            continue;
          }

          removed += 1;
          if (target?.enabled) {
            rolloutCandidates.push({ id: target.id, name: target.name, updatedAt: target.updatedAt, action: 'delete' });
          }
        }

        const plannedRolloutRules = rolloutCandidates.length;

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
            target_agent_commands: 0,
            created: 0,
            deduplicated: 0,
            planned_rules: plannedRolloutRules,
            processed_rules: 0
          },
          message: 'Creating rollout commands for validated rules.'
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
            target_agent_commands: 0,
            created: 0,
            deduplicated: 0,
            planned_rules: plannedRolloutRules,
            processed_rules: 0
          }
        });

        for (const candidate of rolloutCandidates) {
          const rollout = await dispatchRuleRollout(ctx, candidate, candidate.action);
          if (!rollout.queued) {
            processedRolloutRules += 1;
            const rolloutProgress = {
              target_agent_commands: totalDispatchTargets,
              created: totalDispatchCreated,
              deduplicated: totalDispatchDeduplicated,
              planned_rules: plannedRolloutRules,
              processed_rules: processedRolloutRules
            };
            forgeCoreSyncMetadata = {
              ...forgeCoreSyncMetadata,
              rollout: rolloutProgress
            };
            updateYaraForgeSyncState({ rollout: rolloutProgress });
            continue;
          }
          totalDispatchTargets += Number(rollout.agents ?? 0);
          totalDispatchCreated += Number(rollout.dispatched ?? 0);
          totalDispatchDeduplicated += Number(rollout.deduplicated ?? 0);
          processedRolloutRules += 1;
          const rolloutProgress = {
            target_agent_commands: totalDispatchTargets,
            created: totalDispatchCreated,
            deduplicated: totalDispatchDeduplicated,
            planned_rules: plannedRolloutRules,
            processed_rules: processedRolloutRules
          };
          forgeCoreSyncMetadata = {
            ...forgeCoreSyncMetadata,
            rollout: rolloutProgress
          };
          updateYaraForgeSyncState({ rollout: rolloutProgress });
        }

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
            target_agent_commands: totalDispatchTargets,
            created: totalDispatchCreated,
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
          message: 'YARA Forge Core sync completed.',
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

  // Current endpoint: /api/xdr-defense/yara/rollouts/status
  router.get(
    {
      path: '/api/xdr-defense/yara/rollouts/status',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => handleRolloutStatus(ctx, res)
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
      validate: rolloutStatusValidationSchema
    },
    async (ctx: any, req: any, res: any) => handleRolloutStatusIngestion(ctx, req, res)
  );

  // Legacy alias: POST /api/xdr-defense/yara-rollouts/status
  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/status',
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
      validate: ackValidationSchema
    },
    async (ctx: any, req: any, res: any) => handleRolloutAck(ctx, req, res)
  );

  // Legacy alias: /api/xdr-defense/yara-rollouts/ack
  router.post(
    {
      path: '/api/xdr-defense/yara-rollouts/ack',
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
      path: '/api/xdr-defense/yara/bundle/build',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
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

        const result = buildSignedYaraBundle(policyId);
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
}
