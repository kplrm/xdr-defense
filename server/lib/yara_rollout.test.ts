import test from 'node:test';
import assert from 'node:assert/strict';

import { listRolloutStatus } from './yara_rollout';

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function hit(source: Record<string, unknown>) {
  return { _id: String(source.command_id ?? 'cmd'), _source: source };
}

test('listRolloutStatus keeps latest state per agent+rule and suppresses stale history', async () => {
  const client: any = {
    indices: { create: async () => ({}) },
    search: async () => ({
      body: {
        hits: {
          hits: [
            hit({
              command_id: 'old-pending',
              command_key: 'agent-1|rule-1|activate|v1',
              dispatch_version: 'v1',
              agent_id: 'agent-1',
              rule_id: 'rule-1',
              rule_name: 'rule one',
              action: 'activate',
              status: 'pending',
              attempts: 1,
              first_dispatched_at: isoOffset(-35 * 60_000),
              last_dispatched_at: isoOffset(-30 * 60_000)
            }),
            hit({
              command_id: 'new-ack',
              command_key: 'agent-1|rule-1|activate|v2',
              dispatch_version: 'v2',
              agent_id: 'agent-1',
              rule_id: 'rule-1',
              rule_name: 'rule one',
              action: 'activate',
              status: 'acknowledged',
              attempts: 1,
              first_dispatched_at: isoOffset(-5 * 60_000),
              last_dispatched_at: isoOffset(-1 * 60_000),
              acknowledged_at: isoOffset(-1 * 60_000)
            })
          ]
        }
      }
    })
  };

  const status = await listRolloutStatus(client);

  assert.equal(status.summary.total_commands, 1);
  assert.equal(status.summary.acknowledged, 1);
  assert.equal(status.summary.pending, 0);
  assert.equal(status.summary.failed, 0);
  assert.equal(status.summary.retryable, 0);
  assert.equal(status.failures.length, 0);
  assert.equal(status.rules['rule-1']?.acknowledged, 1);
});

test('listRolloutStatus reports stale pending when latest state is pending past timeout', async () => {
  const client: any = {
    indices: { create: async () => ({}) },
    search: async () => ({
      body: {
        hits: {
          hits: [
            hit({
              command_id: 'only-pending',
              command_key: 'agent-2|rule-2|activate|v1',
              dispatch_version: 'v1',
              agent_id: 'agent-2',
              rule_id: 'rule-2',
              rule_name: 'rule two',
              action: 'activate',
              status: 'pending',
              attempts: 2,
              first_dispatched_at: isoOffset(-40 * 60_000),
              last_dispatched_at: isoOffset(-20 * 60_000)
            })
          ]
        }
      }
    })
  };

  const status = await listRolloutStatus(client);

  assert.equal(status.summary.total_commands, 1);
  assert.equal(status.summary.retryable, 1);
  assert.equal(status.failures.length, 1);
  assert.match(status.failures[0].failure_reason ?? '', /No ACK received after 10 minutes/i);
});
