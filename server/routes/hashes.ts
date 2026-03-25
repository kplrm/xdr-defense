declare const require: any;

import {
  addCustomHashRule,
  buildSignedHashBundle,
  deleteHashRule,
  getExistingMalwareBazaarHashRuleState,
  getHashRule,
  getHashSigningReadiness,
  listHashRules,
  updateHashRule,
  upsertMalwareBazaarHashRule
} from '../lib/hashes_store';
import { fetchMalwareBazaarHashes } from '../lib/malwarebazaar';
import { getMalwareBazaarApiKey, getMalwareBazaarApiKeyStatus, setMalwareBazaarApiKey } from '../lib/secret_store';
import { getMalwareBazaarSyncState, updateMalwareBazaarSyncState } from '../lib/upstream_sync_store';

const { schema } = require('@osd/config-schema');

const MALWARE_BAZAAR_RULE_ID = 'malwarebazaar-recent-feed';
const MALWARE_BAZAAR_RULE_NAME = 'MalwareBazaar Recent Malicious Hash Feed';
const MALWARE_BAZAAR_MAX_HASHES = 5000;

function parseSha256Set(content: string): Set<string> {
  const hashes = new Set<string>();
  for (const line of String(content ?? '').split(/\r?\n/)) {
    const normalized = line.trim().toLowerCase();
    const match = normalized.match(/^sha256:([a-f0-9]{64})$/) ?? normalized.match(/^([a-f0-9]{64})$/);
    if (match) {
      hashes.add(match[1]);
    }
  }
  return hashes;
}

function buildHashFeedContent(hashes: string[]): string {
  return hashes.map((hash) => `sha256:${hash}`).join('\n');
}

function malwareBazaarStatusBody(): Record<string, unknown> {
  const sync = getMalwareBazaarSyncState();
  const secretStatus = getMalwareBazaarApiKeyStatus();
  return {
    api_key_configured: secretStatus.configured,
    api_key_updated_at: secretStatus.updated_at ?? sync.api_key_updated_at,
    last_attempted_at: sync.last_attempted_at,
    last_completed_at: sync.last_completed_at,
    last_successful_sync_at: sync.last_successful_sync_at,
    last_cursor_seen_at: sync.last_cursor_seen_at,
    last_query_mode: sync.last_query_mode,
    last_upstream_records: sync.last_upstream_records,
    last_new_hashes: sync.last_new_hashes,
    last_total_hashes: sync.last_total_hashes,
    last_error: sync.last_error
  };
}

async function performMalwareBazaarSync(): Promise<Record<string, unknown>> {
  const apiKey = getMalwareBazaarApiKey();
  if (!apiKey) {
    throw new Error('Configure a MalwareBazaar API key before syncing hashes.');
  }

  const syncState = getMalwareBazaarSyncState();
  const startedAt = new Date().toISOString();
  const feed = await fetchMalwareBazaarHashes({
    apiKey,
    lastSuccessfulSyncAt: syncState.last_successful_sync_at
  });

  const existing = getHashRule(MALWARE_BAZAAR_RULE_ID);
  const mergedHashes = parseSha256Set(existing?.content ?? '');
  let newHashes = 0;
  for (const sample of feed.samples) {
    if (!mergedHashes.has(sample.sha256_hash)) {
      mergedHashes.add(sample.sha256_hash);
      newHashes += 1;
    }
  }

  const sortedHashes = [...mergedHashes].sort((a, b) => a.localeCompare(b)).slice(-MALWARE_BAZAAR_MAX_HASHES);
  const content = buildHashFeedContent(sortedHashes);
  const existingState = getExistingMalwareBazaarHashRuleState(MALWARE_BAZAAR_RULE_ID);
  const upserted = upsertMalwareBazaarHashRule({
    id: MALWARE_BAZAAR_RULE_ID,
    name: MALWARE_BAZAAR_RULE_NAME,
    content,
    severity: 'critical',
    tags: ['malwarebazaar', 'recent', 'api-synced'],
    enabled: existingState ? existingState.enabled : true
  });

  const completedAt = new Date().toISOString();
  updateMalwareBazaarSyncState({
    last_attempted_at: startedAt,
    last_completed_at: completedAt,
    last_successful_sync_at: completedAt,
    last_cursor_seen_at: feed.cursor_seen_at,
    last_query_mode: feed.query_mode,
    last_upstream_records: feed.samples.length,
    last_new_hashes: newHashes,
    last_total_hashes: sortedHashes.length,
    last_error: undefined
  });

  return {
    message: 'MalwareBazaar hash sync completed.',
    query_mode: feed.query_mode,
    upstream_records: feed.samples.length,
    new_hashes: newHashes,
    total_hashes: sortedHashes.length,
    imported: upserted.changed ? 1 : 0,
    unchanged: upserted.changed ? 0 : 1,
    load_failures: 0,
    errors: [],
    status: malwareBazaarStatusBody()
  };
}

export function registerHashRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr-defense/hashes/rules',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        return res.ok({ body: { rules: listHashRules() } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to list hash rules.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/config',
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => res.ok({ body: malwareBazaarStatusBody() })
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/config',
      validate: {
        body: schema.object({
          api_key: schema.string({ minLength: 1, maxLength: 512 })
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const saved = setMalwareBazaarApiKey(req.body?.api_key ?? '');
        updateMalwareBazaarSyncState({ api_key_updated_at: saved.updated_at, last_error: undefined });
        return res.ok({ body: malwareBazaarStatusBody() });
      } catch (err: any) {
        return res.customError({
          statusCode: 400,
          body: {
            message: 'Failed to save MalwareBazaar API key.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/rules',
      validate: {
        body: schema.object({
          name: schema.string({ minLength: 1, maxLength: 160 }),
          content: schema.string({ minLength: 1, maxLength: 200000 }),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 32 })),
          tags: schema.maybe(schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 32 }))
        })
      }
    },
    async (_ctx: any, req: any, res: any) => {
      try {
        const created = addCustomHashRule(req.body ?? {});
        if (created.validation.status === 'invalid') {
          return res.customError({
            statusCode: 400,
            body: {
              message: 'Hash rule validation failed.',
              rule: created,
              validation: created.validation
            }
          });
        }
        return res.ok({ body: created });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to create hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.put(
    {
      path: '/api/xdr-defense/hashes/rules/{id}',
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
    async (_ctx: any, req: any, res: any) => {
      try {
        const result = updateHashRule(req.params.id, req.body ?? {});
        if (!result.updated) {
          return res.customError({
            statusCode: result.error === 'Rule not found.' ? 404 : 400,
            body: { message: result.error ?? 'Failed to update hash rule.' }
          });
        }
        return res.ok({ body: result.updated });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to update hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.delete(
    {
      path: '/api/xdr-defense/hashes/rules/{id}',
      validate: {
        params: schema.object({ id: schema.string({ minLength: 1, maxLength: 256 }) })
      }
    },
    async (_ctx: any, req: any, res: any) => {
      try {
        const result = deleteHashRule(req.params.id);
        if (!result.deleted) {
          return res.customError({
            statusCode: result.error === 'Rule not found.' ? 404 : 400,
            body: { message: result.error ?? 'Failed to delete hash rule.' }
          });
        }
        return res.ok({ body: { deleted: true, id: req.params.id } });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to delete hash rule.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-defense/hashes/bundle',
      validate: {
        query: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const policyId = String(req.query?.policy_id ?? 'global-default');
        const readiness = getHashSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed hash bundle generation unavailable.',
              details: readiness.reason
            }
          });
        }

        const result = buildSignedHashBundle(policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signed hash bundle generation unavailable.',
              details: result.error ?? 'Failed to sign bundle.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build hash bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/bundle/build',
      validate: {
        body: schema.object({
          policy_id: schema.maybe(schema.string({ minLength: 1, maxLength: 256 }))
        })
      }
    },
    async (_ctx: unknown, req: any, res: any) => {
      try {
        const policyId = String(req.body?.policy_id ?? 'global-default');
        const readiness = getHashSigningReadiness();
        if (!readiness.ready) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Hash bundle signing unavailable.',
              details: readiness.reason
            }
          });
        }

        const result = buildSignedHashBundle(policyId);
        if (!result.bundle) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Hash bundle generation failed.',
              details: result.error ?? 'Unknown error.'
            }
          });
        }

        return res.ok({ body: result.bundle });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to build hash bundle.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );

  const syncHandler = async (_ctx: any, _req: any, res: any) => {
    try {
      const result = await performMalwareBazaarSync();
      return res.ok({ body: result });
    } catch (err: any) {
      updateMalwareBazaarSyncState({
        last_attempted_at: new Date().toISOString(),
        last_completed_at: new Date().toISOString(),
        last_error: String(err?.message ?? err)
      });
      return res.customError({
        statusCode: String(err?.message ?? err).includes('Configure a MalwareBazaar API key') ? 400 : 502,
        body: {
          message: 'Failed to sync MalwareBazaar hashes.',
          details: String(err?.message ?? err),
          status: malwareBazaarStatusBody()
        }
      });
    }
  };

  router.post(
    {
      path: '/api/xdr-defense/hashes/malwarebazaar/sync',
      validate: false
    },
    syncHandler
  );

  router.post(
    {
      path: '/api/xdr-defense/hashes/open-source/sync',
      validate: false
    },
    syncHandler
  );
}
