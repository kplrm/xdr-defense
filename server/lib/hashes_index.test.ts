import test from 'node:test';
import assert from 'node:assert/strict';

import { isEligibleHashBundleRule } from './hashes_index';

test('isEligibleHashBundleRule accepts valid critical entries from MalwareBazaar sources', () => {
  const apiSourceRule = isEligibleHashBundleRule({
    enabled: true,
    severity: 'critical',
    source: 'malwarebazaar_api',
    validation: { status: 'valid' }
  });
  const csvSourceRule = isEligibleHashBundleRule({
    enabled: true,
    severity: 'crit',
    source: 'malwarebazaar_full_csv',
    validation: { status: 'valid' }
  });

  assert.equal(apiSourceRule, true);
  assert.equal(csvSourceRule, true);
});

test('isEligibleHashBundleRule rejects high severity even when enabled and valid', () => {
  const eligible = isEligibleHashBundleRule({
    enabled: true,
    severity: 'high',
    validation: { status: 'valid' }
  });

  assert.equal(eligible, false);
});
