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
import { loadForgeCoreSources, syncForgeCoreWithWorkerPool } from '../lib/yara_forge';
import {
  acknowledgeRollout,
  dispatchRolloutForAgents,
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
      try {
        const sources = await loadForgeCoreSources();
        const syncResult = await syncForgeCoreWithWorkerPool(sources);

        let imported = 0;
        let unchanged = 0;
        let activeRulesQueued = 0;
        let totalDispatchTargets = 0;
        let totalDispatchCreated = 0;
        let totalDispatchDeduplicated = 0;
        const importErrors: string[] = [];

        const sourceById = new Map<string, (typeof sources)[number]>();
        for (const source of sources) {
          sourceById.set(source.id, source);
        }

        for (const item of syncResult.items) {
          if (!item.ok || !item.content) {
            importErrors.push(`${item.id}: ${item.error ?? 'load failed'}`);
            continue;
          }

          const source = sourceById.get(item.id);
          const existingState = getExistingForgeCoreRuleState(item.id);
          const upserted = upsertForgeCoreYaraRule({
            id: item.id,
            name: item.name,
            content: item.content,
            severity: source?.severity ?? 'medium',
            tags: source?.tags ?? ['forge-core', 'synced'],
            enabled: existingState ? existingState.enabled : true
          });

          if (!upserted.changed) {
            unchanged += 1;
          } else {
            imported += 1;
          }

          if (upserted.rule.enabled) {
            activeRulesQueued += 1;
            const rollout = await dispatchRuleRollout(
              ctx,
              { id: upserted.rule.id, name: upserted.rule.name, updatedAt: upserted.rule.updatedAt },
              'activate'
            );
            if (rollout.queued) {
              totalDispatchTargets += Number(rollout.agents ?? 0);
              totalDispatchCreated += Number(rollout.dispatched ?? 0);
              totalDispatchDeduplicated += Number(rollout.deduplicated ?? 0);
            }
          }
        }

        return res.ok({
          body: {
            message: 'YARA Forge Core sync completed.',
            parallel_workers: syncResult.worker_count,
            attempted: syncResult.attempted,
            loaded: syncResult.succeeded,
            load_failures: syncResult.failed,
            imported,
            unchanged,
            active_rules_queued: activeRulesQueued,
            rollout: {
              target_agent_commands: totalDispatchTargets,
              created: totalDispatchCreated,
              deduplicated: totalDispatchDeduplicated
            },
            errors: importErrors.sort((a, b) => a.localeCompare(b))
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to sync YARA Forge Core.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/yara/rollouts/status',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => {
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
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/rollouts/retry',
      validate: false
    },
    async (ctx: any, _req: any, res: any) => {
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
  );

  router.post(
    {
      path: '/api/xdr-defense/yara/rollouts/ack',
      validate: {
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
      }
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
