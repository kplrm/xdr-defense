declare const require: any;

import test from 'node:test';
import assert from 'node:assert/strict';

test('reconcileImmediateCustomHashOverlayState tracks eligible custom hashes and bumps bundle version', () => {
  const originalDataDir = process.env.XDR_DEFENSE_DATA_DIR;
  process.env.XDR_DEFENSE_DATA_DIR = require('fs').mkdtempSync(`${require('os').tmpdir()}/xdr-defense-overlay-`);

  try {
    const modulePath = require.resolve('./hash_custom_overlay_state');
    delete require.cache[modulePath];
    const overlay = require('./hash_custom_overlay_state') as typeof import('./hash_custom_overlay_state');

    const created = overlay.reconcileImmediateCustomHashOverlayState([
      {
        id: 'custom-abc',
        forceVersionBump: true,
        doc: {
          source: 'custom',
          enabled: true,
          severity: 'critical',
          sha256_hash: 'a'.repeat(64),
          updated_at: '2026-03-27T00:00:00.000Z',
          name: 'custom-a',
          tags: [],
          content: 'sha256:' + 'a'.repeat(64),
          validation: {
            status: 'valid',
            errors: [],
            warnings: [],
            checkedAt: '2026-03-27T00:00:00.000Z'
          }
        }
      }
    ]);

    assert.equal(created.bundle_version, 1);
    assert.deepEqual(created.pending_doc_ids, ['custom-abc']);

    const updated = overlay.reconcileImmediateCustomHashOverlayState([
      {
        id: 'custom-abc',
        forceVersionBump: true,
        doc: {
          source: 'custom',
          enabled: true,
          severity: 'crit',
          sha256_hash: 'a'.repeat(64),
          updated_at: '2026-03-27T00:05:00.000Z',
          name: 'custom-a-updated',
          tags: [],
          content: 'sha256:' + 'a'.repeat(64),
          validation: {
            status: 'valid',
            errors: [],
            warnings: [],
            checkedAt: '2026-03-27T00:05:00.000Z'
          }
        }
      }
    ]);

    assert.equal(updated.bundle_version, 2);
    assert.deepEqual(updated.pending_doc_ids, ['custom-abc']);

    const removed = overlay.reconcileImmediateCustomHashOverlayState([{ id: 'custom-abc', doc: null }]);
    assert.equal(removed.bundle_version, 3);
    assert.deepEqual(removed.pending_doc_ids, []);
  } finally {
    if (originalDataDir === undefined) {
      delete process.env.XDR_DEFENSE_DATA_DIR;
    } else {
      process.env.XDR_DEFENSE_DATA_DIR = originalDataDir;
    }
  }
});

test('clearImmediateCustomHashOverlayState preserves empty state and clears populated state', () => {
  const originalDataDir = process.env.XDR_DEFENSE_DATA_DIR;
  process.env.XDR_DEFENSE_DATA_DIR = require('fs').mkdtempSync(`${require('os').tmpdir()}/xdr-defense-overlay-`);

  try {
    const modulePath = require.resolve('./hash_custom_overlay_state');
    delete require.cache[modulePath];
    const overlay = require('./hash_custom_overlay_state') as typeof import('./hash_custom_overlay_state');

    const empty = overlay.clearImmediateCustomHashOverlayState();
    assert.equal(empty.bundle_version, 0);
    assert.deepEqual(empty.pending_doc_ids, []);

    overlay.reconcileImmediateCustomHashOverlayState([
      {
        id: 'custom-def',
        forceVersionBump: true,
        doc: {
          source: 'custom',
          enabled: true,
          severity: 'critical',
          sha256_hash: 'b'.repeat(64),
          updated_at: '2026-03-27T00:00:00.000Z',
          name: 'custom-b',
          tags: [],
          content: 'sha256:' + 'b'.repeat(64),
          validation: {
            status: 'valid',
            errors: [],
            warnings: [],
            checkedAt: '2026-03-27T00:00:00.000Z'
          }
        }
      }
    ]);

    const cleared = overlay.clearImmediateCustomHashOverlayState();
    assert.equal(cleared.bundle_version, 2);
    assert.deepEqual(cleared.pending_doc_ids, []);
  } finally {
    if (originalDataDir === undefined) {
      delete process.env.XDR_DEFENSE_DATA_DIR;
    } else {
      process.env.XDR_DEFENSE_DATA_DIR = originalDataDir;
    }
  }
});