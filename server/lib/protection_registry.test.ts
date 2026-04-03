import { validateProtectionRuleContent } from './protection_registry';

describe('validateProtectionRuleContent', () => {
  it('returns invalid for empty content', () => {
    const result = validateProtectionRuleContent('');
    expect(result.status).toBe('invalid');
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid for YAML rules content', () => {
    const result = validateProtectionRuleContent([
      'rules:',
      '  - id: test-memory-rule',
      '    name: "Test rule"',
      '    description: "Detect suspicious memory activity"',
      '    severity: high',
      '    condition:',
      '      event_type: "process.start"',
      '      command_line: ".*memfd_create.*"',
      '    action: alert',
      '    enabled: true',
      '    tags: ["memory"]'
    ].join('\n'));
    expect(result.status).toBe('valid');
    expect(result.errors).toEqual([]);
  });
});
