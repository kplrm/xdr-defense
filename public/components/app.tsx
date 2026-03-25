import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCheckbox,
  EuiCodeBlock,
  EuiFieldSearch,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiHorizontalRule,
  EuiInMemoryTable,
  EuiLoadingSpinner,
  EuiPagination,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

interface RuleValidation {
  status: 'valid' | 'invalid';
  errors: string[];
  warnings: string[];
  checkedAt: string;
}

interface ManagedRule {
  id: string;
  name: string;
  source: string;
  enabled: boolean;
  severity: string;
  tags: string[];
  updatedAt: string;
  validation: RuleValidation;
}

interface RulesResponse {
  rules: ManagedRule[];
}

interface YaraTestResponse {
  validation: RuleValidation;
  simulation: {
    queried: boolean;
    lookback_minutes: number;
    total_hits: number;
    simulated_matches: number;
    query_error?: string;
  };
}

interface SignedBundle {
  manifest_version: number;
  policy_id: string;
  bundle_version: number;
  generated_at: string;
  signing_alg: string;
  rules: Array<{ id: string; filename: string; enabled: boolean; source: string; updatedAt: string }>;
  active_checksums: string[];
  signature_base64: string;
  signed_payload_base64: string;
}

interface BundleMetadata {
  bundle_version: number;
  generated_at: string;
  activated_at?: string;
  policy_id: string;
  active_checksums: string[];
  rule_count: number;
  enabled_rule_count: number;
}

interface RuleRolloutSummary {
  pending: number;
  acknowledged: number;
  failed: number;
  last_action?: 'activate' | 'deactivate' | 'delete';
  last_dispatched_at?: string;
}

interface RolloutFailureRecord {
  command_id: string;
  dispatch_version: string;
  agent_id: string;
  agent_hostname?: string;
  rule_id: string;
  rule_name: string;
  action: 'activate' | 'deactivate' | 'delete';
  status: 'pending' | 'acknowledged' | 'failed';
  attempts: number;
  last_dispatched_at: string;
  acknowledged_at?: string;
  failure_reason?: string;
  retryable: boolean;
}

interface RolloutStatusResponse {
  summary: {
    total_commands: number;
    pending: number;
    acknowledged: number;
    failed: number;
    retryable: number;
    stale_timeout_minutes: number;
    generated_at: string;
  };
  failures: RolloutFailureRecord[];
  rules: Record<string, RuleRolloutSummary>;
}

interface ForgeCoreSyncMetadata {
  status: 'idle' | 'processing' | 'completed' | 'failed';
  phase?: 'idle' | 'downloading' | 'validating' | 'rollout' | 'completed' | 'failed';
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

interface MalwareBazaarStatus {
  api_key_configured: boolean;
  api_key_updated_at?: string;
  last_attempted_at?: string;
  last_completed_at?: string;
  last_successful_sync_at?: string;
  last_cursor_seen_at?: string;
  last_query_mode?: string;
  last_upstream_records?: number;
  last_new_hashes?: number;
  last_total_hashes?: number;
  last_error?: string;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface XdrDefenseAppProps {
  basename: string;
  http: CoreStart['http'];
  notifications: CoreStart['notifications'];
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const XdrDefenseApp: React.FC<XdrDefenseAppProps> = ({ http, notifications }) => {
  // ---- Tab ----
  const [activeTab, setActiveTab] = useState('detection-content');

  // ---- Rule data ----
  const [yaraRules, setYaraRules] = useState<ManagedRule[]>([]);
  const [hashRules, setHashRules] = useState<ManagedRule[]>([]);
  const [behavioralRules, setBehavioralRules] = useState<ManagedRule[]>([]);
  const [bundleMetadata, setBundleMetadata] = useState<BundleMetadata | null>(null);
  const [rolloutStatus, setRolloutStatus] = useState<RolloutStatusResponse | null>(null);
  const [yaraForgeSyncStatus, setYaraForgeSyncStatus] = useState<ForgeCoreSyncMetadata | null>(null);
  const [isSyncingYaraForge, setIsSyncingYaraForge] = useState(false);
  const [malwareBazaarStatus, setMalwareBazaarStatus] = useState<MalwareBazaarStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // ---- UI state ----
  const [drawerOpen, setDrawerOpen] = useState<'none' | 'yara' | 'hashes' | 'behavioral' | 'malwarebazaar-config'>('none');
  const [banner, setBanner] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  // ---- YARA pagination / search / selection ----
  const [yaraSearchQuery, setYaraSearchQuery] = useState('');
  const [yaraPageSize, setYaraPageSize] = useState(20);
  const [yaraPageIndex, setYaraPageIndex] = useState(0);
  const [selectedYaraIds, setSelectedYaraIds] = useState<Set<string>>(new Set());
  const [isYaraBusy, setIsYaraBusy] = useState(false);

  // ---- YARA form ----
  const [yaraFormName, setYaraFormName] = useState('');
  const [yaraFormContent, setYaraFormContent] = useState('');
  const [yaraFormSeverity, setYaraFormSeverity] = useState('medium');
  const [yaraFormTags, setYaraFormTags] = useState('');

  // ---- Hash form ----
  const [hashFormName, setHashFormName] = useState('');
  const [hashFormContent, setHashFormContent] = useState('');
  const [hashFormSeverity, setHashFormSeverity] = useState('medium');
  const [hashFormTags, setHashFormTags] = useState('');
  const [malwareBazaarApiKey, setMalwareBazaarApiKey] = useState('');

  // ---- Behavioral form ----
  const [behavioralFormName, setBehavioralFormName] = useState('');
  const [behavioralFormContent, setBehavioralFormContent] = useState('');
  const [behavioralFormSeverity, setBehavioralFormSeverity] = useState('medium');
  const [behavioralFormTags, setBehavioralFormTags] = useState('');

  // ---- Testing ----
  const [testSampleText, setTestSampleText] = useState('');
  const [testLookback, setTestLookback] = useState('60');
  const [testContent, setTestContent] = useState('');
  const [testOutput, setTestOutput] = useState('No test run yet.');

  // ---------------------------------------------------------------------------
  // API helpers
  // ---------------------------------------------------------------------------

  const refreshYaraRules = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/yara/rules')) as RulesResponse;
      setYaraRules(Array.isArray(payload?.rules) ? payload.rules : []);
    } catch (err: unknown) {
      setBanner({ kind: 'error', message: `Failed to load YARA rules: ${String((err as Error)?.message ?? err)}` });
    }
  }, [http]);

  const refreshHashRules = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/hashes/rules')) as RulesResponse;
      setHashRules(Array.isArray(payload?.rules) ? payload.rules : []);
    } catch (err: unknown) {
      setBanner({ kind: 'error', message: `Failed to load hash rules: ${String((err as Error)?.message ?? err)}` });
    }
  }, [http]);

  const refreshBehavioralRules = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/behavioral/rules')) as RulesResponse;
      setBehavioralRules(Array.isArray(payload?.rules) ? payload.rules : []);
    } catch (err: unknown) {
      setBanner({ kind: 'error', message: `Failed to load behavioral rules: ${String((err as Error)?.message ?? err)}` });
    }
  }, [http]);

  const refreshBundleMetadata = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/yara/bundle?policy_id=global-default')) as SignedBundle;
      if (payload?.manifest_version) {
        setBundleMetadata({
          bundle_version: payload.bundle_version,
          generated_at: payload.generated_at,
          policy_id: payload.policy_id,
          active_checksums: payload.active_checksums || [],
          rule_count: (payload.rules || []).length,
          enabled_rule_count: (payload.rules || []).filter((r) => r.enabled).length,
        });
      }
    } catch {
      // Bundle may not exist yet
    }
  }, [http]);

  const refreshRolloutStatus = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/yara/rollouts/status')) as RolloutStatusResponse;
      setRolloutStatus(payload);
    } catch {
      setRolloutStatus(null);
    }
  }, [http]);

  const refreshYaraForgeSyncStatus = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/yara/forge-core/status')) as ForgeCoreSyncMetadata;
      setYaraForgeSyncStatus(payload);
      setIsSyncingYaraForge(payload?.status === 'processing');
    } catch {
      setYaraForgeSyncStatus(null);
      setIsSyncingYaraForge(false);
    }
  }, [http]);

  const refreshMalwareBazaarStatus = useCallback(async () => {
    try {
      const payload = (await http.get('/api/xdr-defense/hashes/malwarebazaar/config')) as MalwareBazaarStatus;
      setMalwareBazaarStatus(payload);
    } catch {
      setMalwareBazaarStatus(null);
    }
  }, [http]);

  const refreshAll = useCallback(async () => {
    await Promise.all([
      refreshYaraRules(),
      refreshHashRules(),
      refreshBehavioralRules(),
      refreshBundleMetadata(),
      refreshRolloutStatus(),
      refreshYaraForgeSyncStatus(),
      refreshMalwareBazaarStatus(),
    ]);
  }, [refreshYaraRules, refreshHashRules, refreshBehavioralRules, refreshBundleMetadata, refreshRolloutStatus, refreshYaraForgeSyncStatus, refreshMalwareBazaarStatus]);

  useEffect(() => {
    setIsLoading(true);
    refreshAll().finally(() => setIsLoading(false));
  }, [refreshAll]);

  useEffect(() => {
    if (!isSyncingYaraForge && yaraForgeSyncStatus?.status !== 'processing') {
      return;
    }

    const intervalId = window.setInterval(() => {
      refreshYaraForgeSyncStatus();
    }, 750);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [isSyncingYaraForge, yaraForgeSyncStatus?.status, refreshYaraForgeSyncStatus]);

  // ---------------------------------------------------------------------------
  // YARA tab — filtered + paged rows (computed before columns for select-all)
  // ---------------------------------------------------------------------------

  const filteredYaraRules = yaraRules
    .filter((rule) => {
      const q = yaraSearchQuery.toLowerCase();
      return !q || rule.name.toLowerCase().includes(q) || rule.tags.some((t) => t.toLowerCase().includes(q));
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const yaraTotal = filteredYaraRules.length;
  const yaraTotalPages = Math.max(1, Math.ceil(yaraTotal / yaraPageSize));
  const yaraCurrentPage = Math.min(yaraPageIndex, yaraTotalPages - 1);
  const pagedYaraRules = filteredYaraRules.slice(yaraCurrentPage * yaraPageSize, (yaraCurrentPage + 1) * yaraPageSize);

  const allPageSelected = pagedYaraRules.length > 0 && pagedYaraRules.every((r) => selectedYaraIds.has(r.id));
  const somePageSelected = pagedYaraRules.some((r) => selectedYaraIds.has(r.id));

  // ---------------------------------------------------------------------------
  // YARA tab columns
  // ---------------------------------------------------------------------------

  const yaraColumns = [
    {
      name: (
        <EuiCheckbox
          id="yara-select-all"
          label=""
          checked={allPageSelected}
          indeterminate={somePageSelected && !allPageSelected}
          onChange={() => {
            if (allPageSelected) {
              setSelectedYaraIds((prev) => {
                const next = new Set(prev);
                pagedYaraRules.forEach((r) => next.delete(r.id));
                return next;
              });
            } else {
              setSelectedYaraIds((prev) => {
                const next = new Set(prev);
                pagedYaraRules.forEach((r) => next.add(r.id));
                return next;
              });
            }
          }}
        />
      ),
      width: '40px',
      render: (rule: ManagedRule) => (
        <EuiCheckbox
          id={`yara-sel-${rule.id}`}
          label=""
          checked={selectedYaraIds.has(rule.id)}
          onChange={() => {
            setSelectedYaraIds((prev) => {
              const next = new Set(prev);
              if (next.has(rule.id)) next.delete(rule.id);
              else next.add(rule.id);
              return next;
            });
          }}
        />
      ),
    },
    { field: 'name', name: 'Name' },
    { field: 'source', name: 'Source' },
    { field: 'severity', name: 'Severity' },
    {
      field: 'tags',
      name: 'Tags',
      render: (tags: string[]) => tags.join(', '),
    },
    {
      field: 'validation',
      name: 'Validation',
      render: (v: RuleValidation) => (
        <>
          <EuiBadge color={v.status === 'valid' ? 'success' : 'danger'}>{v.status}</EuiBadge>
          {v.errors.length > 0 && (
            <EuiText size="xs" color="danger">
              <p>{v.errors.join('; ')}</p>
            </EuiText>
          )}
        </>
      ),
    },
    {
      name: 'State',
      render: (rule: ManagedRule) => (
        <EuiSwitch
          label="enabled"
          checked={rule.enabled}
          disabled={rule.validation.status === 'invalid'}
          compressed
          onChange={async (e) => {
            try {
              await http.put(`/api/xdr-defense/yara/rules/${encodeURIComponent(rule.id)}`, {
                body: JSON.stringify({ enabled: (e.target as HTMLInputElement).checked }),
              });
              await refreshAll();
              setBanner({ kind: 'success', message: 'YARA rule state updated and rollout command queued.' });
            } catch (err: unknown) {
              setBanner({ kind: 'error', message: `Failed to update YARA rule: ${String((err as Error)?.message ?? err)}` });
              await refreshAll();
            }
          }}
        />
      ),
    },
    {
      field: 'updatedAt',
      name: 'Updated',
      render: (date: string) => new Date(date).toLocaleString(),
    },
  ];

  // ---------------------------------------------------------------------------
  // Hashes tab columns
  // ---------------------------------------------------------------------------

  const hashColumns = [
    { field: 'name', name: 'Name' },
    { field: 'source', name: 'Source' },
    { field: 'severity', name: 'Severity' },
    { field: 'tags', name: 'Tags', render: (tags: string[]) => tags.join(', ') },
    {
      field: 'validation',
      name: 'Validation',
      render: (v: RuleValidation) => (
        <EuiBadge color={v.status === 'valid' ? 'success' : 'danger'}>{v.status}</EuiBadge>
      ),
    },
    {
      name: 'State',
      render: (rule: ManagedRule) => (
        <EuiSwitch
          label="enabled"
          checked={rule.enabled}
          disabled={rule.validation.status === 'invalid'}
          compressed
          onChange={async (e) => {
            try {
              await http.put(`/api/xdr-defense/hashes/rules/${encodeURIComponent(rule.id)}`, {
                body: JSON.stringify({ enabled: (e.target as HTMLInputElement).checked }),
              });
              await refreshHashRules();
              setBanner({ kind: 'success', message: 'Hash rule state updated.' });
            } catch (err: unknown) {
              setBanner({ kind: 'error', message: `Failed to update hash rule: ${String((err as Error)?.message ?? err)}` });
            }
          }}
        />
      ),
    },
    {
      field: 'updatedAt',
      name: 'Updated',
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      name: 'Actions',
      render: (rule: ManagedRule) => (
        <EuiButtonEmpty
          color="danger"
          size="xs"
          onClick={async () => {
            if (!window.confirm('Delete this hash rule from registry?')) return;
            try {
              await http.delete(`/api/xdr-defense/hashes/rules/${encodeURIComponent(rule.id)}`);
              await refreshHashRules();
              setBanner({ kind: 'success', message: 'Hash rule deleted.' });
            } catch (err: unknown) {
              setBanner({ kind: 'error', message: `Failed to delete hash rule: ${String((err as Error)?.message ?? err)}` });
            }
          }}
        >
          Delete
        </EuiButtonEmpty>
      ),
    },
  ];

  // ---------------------------------------------------------------------------
  // Behavioral tab columns
  // ---------------------------------------------------------------------------

  const behavioralColumns = [
    { field: 'name', name: 'Name' },
    { field: 'source', name: 'Source' },
    { field: 'severity', name: 'Severity' },
    { field: 'tags', name: 'Tags', render: (tags: string[]) => tags.join(', ') },
    {
      field: 'validation',
      name: 'Validation',
      render: (v: RuleValidation) => (
        <EuiBadge color={v.status === 'valid' ? 'success' : 'danger'}>{v.status}</EuiBadge>
      ),
    },
    {
      name: 'State',
      render: (rule: ManagedRule) => (
        <EuiSwitch
          label="enabled"
          checked={rule.enabled}
          disabled={rule.validation.status === 'invalid'}
          compressed
          onChange={async (e) => {
            try {
              await http.put(`/api/xdr-defense/behavioral/rules/${encodeURIComponent(rule.id)}`, {
                body: JSON.stringify({ enabled: (e.target as HTMLInputElement).checked }),
              });
              await refreshBehavioralRules();
              setBanner({ kind: 'success', message: 'Behavioral rule state updated.' });
            } catch (err: unknown) {
              setBanner({ kind: 'error', message: `Failed to update behavioral rule: ${String((err as Error)?.message ?? err)}` });
            }
          }}
        />
      ),
    },
    {
      field: 'updatedAt',
      name: 'Updated',
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      name: 'Actions',
      render: (rule: ManagedRule) => (
        <EuiButtonEmpty
          color="danger"
          size="xs"
          onClick={async () => {
            if (!window.confirm('Delete this behavioral rule from registry?')) return;
            try {
              await http.delete(`/api/xdr-defense/behavioral/rules/${encodeURIComponent(rule.id)}`);
              await refreshBehavioralRules();
              setBanner({ kind: 'success', message: 'Behavioral rule deleted.' });
            } catch (err: unknown) {
              setBanner({ kind: 'error', message: `Failed to delete behavioral rule: ${String((err as Error)?.message ?? err)}` });
            }
          }}
        >
          Delete
        </EuiButtonEmpty>
      ),
    },
  ];

  // ---------------------------------------------------------------------------
  // Rollout failure monitor columns
  // ---------------------------------------------------------------------------

  const rolloutFailureColumns = [
    { field: 'agent_hostname', name: 'Agent', render: (_: string | undefined, row: RolloutFailureRecord) => row.agent_hostname || row.agent_id },
    { field: 'rule_name', name: 'Rule' },
    { field: 'action', name: 'Action' },
    {
      field: 'status',
      name: 'Status',
      render: (s: string) => (
        <EuiBadge color={s === 'acknowledged' ? 'success' : s === 'failed' ? 'danger' : 'warning'}>{s}</EuiBadge>
      ),
    },
    { field: 'attempts', name: 'Attempts' },
    { field: 'last_dispatched_at', name: 'Last Dispatch', render: (d: string) => new Date(d).toLocaleString() },
    { field: 'failure_reason', name: 'Reason', render: (r: string | undefined) => r || 'No ACK yet' },
  ];

  // ---------------------------------------------------------------------------
  // Severity select options (shared)
  // ---------------------------------------------------------------------------

  const severityOptions = [
    { value: 'low', text: 'low' },
    { value: 'medium', text: 'medium' },
    { value: 'high', text: 'high' },
    { value: 'critical', text: 'critical' },
  ];

  const pageSizeOptions = [
    { value: 20, text: '20' },
    { value: 100, text: '100' },
    { value: 500, text: '500' },
  ];

  // ---------------------------------------------------------------------------
  // Tabs
  // ---------------------------------------------------------------------------

  const syncBadgeColor =
    yaraForgeSyncStatus?.status === 'failed'
      ? 'danger'
      : yaraForgeSyncStatus?.status === 'completed'
      ? 'success'
      : yaraForgeSyncStatus?.status === 'processing'
      ? 'warning'
      : 'hollow';

  const isSyncing = isSyncingYaraForge || yaraForgeSyncStatus?.status === 'processing';
  const syncPhase = yaraForgeSyncStatus?.phase;
  const rolloutPlannedRules = yaraForgeSyncStatus?.rollout?.planned_rules;
  const rolloutProcessedRules = yaraForgeSyncStatus?.rollout?.processed_rules;
  const rolloutLegacyTotal = yaraForgeSyncStatus?.rollout?.target_agent_commands ?? 0;
  const rolloutLegacyProcessed = yaraForgeSyncStatus?.rollout?.created ?? 0;
  const rolloutTotal = typeof rolloutPlannedRules === 'number' ? rolloutPlannedRules : rolloutLegacyTotal;
  const rolloutProcessed = typeof rolloutProcessedRules === 'number' ? rolloutProcessedRules : rolloutLegacyProcessed;
  const syncButtonLabel = isSyncing
    ? syncPhase === 'validating'
      ? 'Validating'
      : syncPhase === 'rollout'
      ? `Rollout ${rolloutProcessed}/${rolloutTotal}`
      : 'Downloading'
    : 'Sync YARA Forge Core';

  const renderYaraTab = () => {
    const rollout = rolloutStatus?.summary;
    const activeCount = yaraRules.filter((r) => r.enabled).length;
    const invalidCount = yaraRules.filter((r) => r.validation.status === 'invalid').length;
    const failures = rolloutStatus?.failures ?? [];
    const syncMeta = yaraForgeSyncStatus;
    const selectedList = [...selectedYaraIds];
    const hasSelection = selectedList.length > 0;
    const selectedRules = yaraRules.filter((r) => selectedYaraIds.has(r.id));
    const selectedDeletable = selectedRules.filter((r) => r.source !== 'builtin');

    return (
      <>
        {/* Top panel */}
        <EuiPanel>
          <EuiFlexGroup justifyContent="spaceBetween" alignItems="flexStart" wrap>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s"><h3>Detection Content Registry</h3></EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued"><p>Manage YARA rules with search, pagination, and automatic agent rollout.</p></EuiText>
              <EuiSpacer size="s" />
              <EuiFlexGroup gutterSize="s" wrap>
                <EuiFlexItem grow={false}><EuiBadge color="hollow">total {yaraRules.length}</EuiBadge></EuiFlexItem>
                <EuiFlexItem grow={false}><EuiBadge color="default">active {activeCount}</EuiBadge></EuiFlexItem>
                <EuiFlexItem grow={false}><EuiBadge color="danger">invalid {invalidCount}</EuiBadge></EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          {/* Sync status sub-panel */}
          <EuiPanel color="subdued" paddingSize="s">
            <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" wrap>
              <EuiFlexItem grow={false}>
                <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
                  <EuiFlexItem grow={false}>
                    <EuiBadge color={syncBadgeColor}>sync {syncMeta?.status ?? 'idle'}</EuiBadge>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiText size="xs" color="subdued">
                      <p>
                        {syncMeta?.started_at
                          ? `started ${new Date(syncMeta.started_at).toLocaleString()}`
                          : 'No sync started yet.'}
                        {syncMeta?.completed_at ? ` · completed ${new Date(syncMeta.completed_at).toLocaleString()}` : ''}
                      </p>
                    </EuiText>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty
                  size="xs"
                  onClick={async () => {
                    await refreshYaraForgeSyncStatus();
                  }}
                >
                  Refresh Sync Status
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="xs" />
            <EuiFlexGroup gutterSize="s" wrap>
              {[
                `attempted ${syncMeta?.attempted ?? 0}`,
                `loaded ${syncMeta?.loaded ?? 0}`,
                `imported ${syncMeta?.imported ?? 0}`,
                `unchanged ${syncMeta?.unchanged ?? 0}`,
                `load failures ${syncMeta?.load_failures ?? 0}`,
                `rollout planned ${syncMeta?.rollout?.planned_rules ?? 0}`,
                `rollout processed ${syncMeta?.rollout?.processed_rules ?? 0}`,
                `rollout created ${syncMeta?.rollout?.created ?? 0}`,
                `rollout deduplicated ${syncMeta?.rollout?.deduplicated ?? 0}`,
              ].map((label) => (
                <EuiFlexItem key={label} grow={false}>
                  <EuiText size="xs" color="subdued"><p>{label}</p></EuiText>
                </EuiFlexItem>
              ))}
            </EuiFlexGroup>
            {Array.isArray(syncMeta?.errors) && (syncMeta?.errors?.length ?? 0) > 0 && (
              <EuiText size="xs" color="danger"><p>{syncMeta?.errors?.join(' | ')}</p></EuiText>
            )}
          </EuiPanel>
        </EuiPanel>

        <EuiSpacer size="m" />

        {/* Rollout failure monitor — above rules table */}
        <EuiPanel>
          <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" wrap>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s"><h3>YARA Rollout Failure Monitor</h3></EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    size="s"
                    onClick={async () => {
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/yara/rollouts/retry', {
                          body: JSON.stringify({}),
                        })) as { retried: number };
                        await refreshRolloutStatus();
                        setBanner({ kind: 'success', message: `Retried ${result.retried} rollout command(s).` });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to retry rollout failures: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Retry Pending Failures
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiText size="s" color="subdued">
                    <p>pending {rollout?.pending ?? 0} | acked {rollout?.acknowledged ?? 0} | failed {rollout?.failed ?? 0} | retryable {rollout?.retryable ?? 0}</p>
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="s" />

          {failures.length === 0 ? (
            <EuiText size="s" color="subdued">
              <p>No rollout failures detected. Commands are either acknowledged or still within ACK timeout.</p>
            </EuiText>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <EuiInMemoryTable
                itemId="command_id"
                items={failures}
                columns={rolloutFailureColumns as any}
                pagination={false}
                sorting={false}
              />
            </div>
          )}
        </EuiPanel>

        <EuiSpacer size="m" />

        {/* Yara rules table */}
        <EuiPanel>
          {/* Title + toolbar: Sync+Add left / Enable+Disable+Delete right */}
          <EuiTitle size="s"><h3>Yara rules</h3></EuiTitle>
          <EuiSpacer size="s" />
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup alignItems="center" gutterSize="s" wrap>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    isDisabled={isSyncing}
                    isLoading={isSyncing}
                    onClick={async () => {
                      if (isSyncing) return;
                      setBanner(null);
                      setIsSyncingYaraForge(true);
                      try {
                        const result = (await http.post('/api/xdr-defense/yara/forge-core/sync', {
                          body: JSON.stringify({}),
                        })) as {
                          status: 'completed' | 'running';
                          release_tag?: string;
                          parallel_workers: number;
                          attempted: number;
                          loaded: number;
                          imported: number;
                          unchanged: number;
                          removed?: number;
                          active_rules_queued: number;
                          load_failures: number;
                          rollout: { target_agent_commands: number; created: number; deduplicated: number };
                          errors: string[];
                          metadata?: ForgeCoreSyncMetadata;
                        };
                        if (result.metadata) setYaraForgeSyncStatus(result.metadata);
                        await refreshAll();
                        const errorText =
                          Array.isArray(result.errors) && result.errors.length > 0
                            ? `\nIssues:\n${result.errors.join('\n')}`
                            : '';
                        notifications.toasts.addSuccess(
                          `YARA Forge sync ${result.status === 'running' ? 'already in progress' : 'completed'}${result.release_tag ? ` for release ${result.release_tag}` : ''}. Imported ${result.imported}, removed ${result.removed ?? 0} rules.`
                        );
                        setBanner({
                          kind: 'success',
                          message: `Forge sync ${result.status === 'running' ? 'already in progress' : 'completed'} with ${result.parallel_workers} workers. Attempted ${result.attempted}, loaded ${result.loaded}, imported ${result.imported}, unchanged ${result.unchanged}, removed ${result.removed ?? 0}, load failures ${result.load_failures}. Active rules queued ${result.active_rules_queued}. Rollout targets ${result.rollout?.target_agent_commands ?? 0}, created ${result.rollout?.created ?? 0}, deduplicated ${result.rollout?.deduplicated ?? 0}.${errorText}`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to sync YARA Forge Core', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Failed to sync YARA Forge Core: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        await refreshYaraForgeSyncStatus();
                        setIsSyncingYaraForge(false);
                      }
                    }}
                  >
                    {syncButtonLabel}
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton onClick={() => setDrawerOpen('yara')}>Add Custom Content</EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup alignItems="center" gutterSize="s" wrap>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    size="s"
                    isDisabled={!hasSelection || isYaraBusy}
                    isLoading={isYaraBusy}
                    onClick={async () => {
                      if (!hasSelection || isYaraBusy) return;
                      setIsYaraBusy(true);
                      setBanner(null);
                      let ok = 0; let fail = 0;
                      for (const id of selectedList) {
                        try {
                          await http.put(`/api/xdr-defense/yara/rules/${encodeURIComponent(id)}`, { body: JSON.stringify({ enabled: true }) });
                          ok++;
                        } catch { fail++; }
                      }
                      await refreshAll();
                      setIsYaraBusy(false);
                      setBanner({ kind: 'success', message: `Enabled ${ok} rule(s)${fail > 0 ? `, failed ${fail}` : ''}.` });
                    }}
                  >
                    Enable
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    size="s"
                    isDisabled={!hasSelection || isYaraBusy}
                    isLoading={isYaraBusy}
                    onClick={async () => {
                      if (!hasSelection || isYaraBusy) return;
                      setIsYaraBusy(true);
                      setBanner(null);
                      let ok = 0; let fail = 0;
                      for (const id of selectedList) {
                        try {
                          await http.put(`/api/xdr-defense/yara/rules/${encodeURIComponent(id)}`, { body: JSON.stringify({ enabled: false }) });
                          ok++;
                        } catch { fail++; }
                      }
                      await refreshAll();
                      setIsYaraBusy(false);
                      setBanner({ kind: 'success', message: `Disabled ${ok} rule(s)${fail > 0 ? `, failed ${fail}` : ''}.` });
                    }}
                  >
                    Disable
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    color="danger"
                    fill
                    size="s"
                    isDisabled={selectedDeletable.length === 0 || isYaraBusy}
                    isLoading={isYaraBusy}
                    onClick={async () => {
                      if (selectedDeletable.length === 0 || isYaraBusy) return;
                      if (!window.confirm(`Delete ${selectedDeletable.length} selected rule(s)? This will queue rollout delete commands for enrolled agents.`)) return;
                      setIsYaraBusy(true);
                      setBanner(null);
                      let deleted = 0; let failed = 0;
                      const errors: string[] = [];
                      for (const rule of selectedDeletable) {
                        try {
                          await http.delete(`/api/xdr-defense/yara/rules/${encodeURIComponent(rule.id)}`);
                          deleted++;
                        } catch (err: unknown) {
                          failed++;
                          errors.push(`${rule.name}: ${String((err as Error)?.message ?? err)}`);
                        }
                      }
                      setSelectedYaraIds(new Set());
                      await refreshAll();
                      setIsYaraBusy(false);
                      setBanner({ kind: 'success', message: `Bulk delete completed. Deleted ${deleted}${failed > 0 ? `, failed ${failed}` : ''}.${errors.length > 0 ? `\n${errors.join(' | ')}` : ''}` });
                    }}
                  >
                    Delete
                  </EuiButton>
                </EuiFlexItem>
                {hasSelection && (
                  <EuiFlexItem grow={false}>
                    <EuiText size="xs" color="subdued"><p>{selectedList.length} selected</p></EuiText>
                  </EuiFlexItem>
                )}
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiHorizontalRule margin="s" />

          {/* Search */}
          <EuiFieldSearch
            value={yaraSearchQuery}
            onChange={(e) => {
              setYaraSearchQuery(e.target.value);
              setYaraPageIndex(0);
            }}
            placeholder="Search..."
            fullWidth
            aria-label="Search YARA rules by name or tags"
          />

          <EuiSpacer size="m" />

          {/* Table with horizontal scroll, max height */}
          <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '55vh' }}>
            <div style={{ display: 'inline-block', minWidth: 1280 }}>
              <EuiInMemoryTable
                itemId="id"
                items={pagedYaraRules}
                columns={yaraColumns as any}
                loading={isLoading}
                pagination={false}
                sorting={false}
              />
            </div>
          </div>

          <EuiSpacer size="s" />

          {/* Pagination — coordinator style */}
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiText size="s"><span>Rows per page</span></EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiSelect
                    compressed
                    value={String(yaraPageSize)}
                    onChange={(e) => {
                      setYaraPageSize(Number(e.target.value));
                      setYaraPageIndex(0);
                    }}
                    options={pageSizeOptions.map((o) => ({ value: String(o.value), text: o.text }))}
                  />
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiPagination
                pageCount={yaraTotalPages}
                activePage={yaraCurrentPage}
                onPageClick={setYaraPageIndex}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        {/* YARA drawer */}
        {drawerOpen === 'yara' && (
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="s" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Add Custom YARA Content</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Name">
                    <EuiFieldText value={yaraFormName} onChange={(e) => setYaraFormName(e.target.value)} placeholder="rule name" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 180 }}>
                  <EuiFormRow label="Severity">
                    <EuiSelect options={severityOptions} value={yaraFormSeverity} onChange={(e) => setYaraFormSeverity(e.target.value)} />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiFormRow label="Tags (comma-separated)">
                <EuiFieldText value={yaraFormTags} onChange={(e) => setYaraFormTags(e.target.value)} placeholder="malware, custom" />
              </EuiFormRow>
              <EuiSpacer size="m" />
              <EuiFormRow label="Rule Content">
                <EuiTextArea
                  value={yaraFormContent}
                  onChange={(e) => setYaraFormContent(e.target.value)}
                  placeholder={'rule my_rule {\n  strings:\n    $a = "sample"\n  condition:\n    $a\n}'}
                  style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', minHeight: 120 }}
                />
              </EuiFormRow>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty onClick={() => setDrawerOpen('none')}>Cancel</EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      try {
                        await http.post('/api/xdr-defense/yara/rules', {
                          body: JSON.stringify({
                            name: yaraFormName,
                            content: yaraFormContent,
                            severity: yaraFormSeverity,
                            tags: yaraFormTags.split(',').map((t) => t.trim()).filter((t) => t.length > 0),
                          }),
                        });
                        setDrawerOpen('none');
                        setYaraFormName('');
                        setYaraFormContent('');
                        setYaraFormSeverity('medium');
                        setYaraFormTags('');
                        await refreshAll();
                        setBanner({ kind: 'success', message: 'Custom YARA rule added and rollout queued for enrolled agents.' });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to add YARA rule: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Add Rule
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutFooter>
          </EuiFlyout>
        )}
      </>
    );
  };

  const renderHashesTab = () => {
    const status = malwareBazaarStatus;
    const sortedHashRules = hashRules.slice().sort((a, b) => a.name.localeCompare(b.name));

    return (
      <>
        <EuiPanel>
          <EuiFlexGroup justifyContent="spaceBetween" alignItems="flexStart" wrap>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s"><h3>Hash Reputation Registry</h3></EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued">
                <p>Manage persisted hash reputation entries sourced from MalwareBazaar and custom operator content.</p>
              </EuiText>
              <EuiSpacer size="s" />
              <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
                <EuiFlexItem grow={false}>
                  <EuiBadge color={status?.api_key_configured ? 'success' : 'warning'}>
                    API key {status?.api_key_configured ? 'configured' : 'missing'}
                  </EuiBadge>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiText size="xs" color="subdued">
                    <p>
                      {status?.last_successful_sync_at
                        ? `last sync ${new Date(status.last_successful_sync_at).toLocaleString()}`
                        : 'No successful MalwareBazaar sync yet.'}
                      {status?.last_query_mode ? ` · mode ${status.last_query_mode}` : ''}
                      {status?.last_total_hashes !== undefined ? ` · stored ${status.last_total_hashes}` : ''}
                    </p>
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s">
                <EuiFlexItem grow={false}>
                  <EuiButtonIcon
                    iconType="gear"
                    aria-label="Configure MalwareBazaar API key"
                    onClick={() => setDrawerOpen('malwarebazaar-config')}
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/hashes/malwarebazaar/sync', {
                          body: JSON.stringify({}),
                        })) as {
                          query_mode: string;
                          upstream_records: number;
                          new_hashes: number;
                          total_hashes: number;
                          imported: number;
                          unchanged: number;
                          load_failures: number;
                          errors: string[];
                        };
                        await refreshHashRules();
                        await refreshMalwareBazaarStatus();
                        const errorText = Array.isArray(result.errors) && result.errors.length > 0 ? `\nErrors:\n${result.errors.join('\n')}` : '';
                        notifications.toasts.addSuccess(
                          `MalwareBazaar sync complete. Added ${result.new_hashes} new hashes, stored ${result.total_hashes} total.`
                        );
                        setBanner({
                          kind: 'success',
                          message: `MalwareBazaar hash sync completed. Upstream records ${result.upstream_records}, new hashes ${result.new_hashes}, imported ${result.imported}, unchanged ${result.unchanged}, load failures ${result.load_failures}.${errorText}`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to sync MalwareBazaar hashes', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Failed to sync MalwareBazaar hashes: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Sync MalwareBazaar Hash Feed
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton onClick={() => setDrawerOpen('hashes')}>Add Custom Hashes</EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        <EuiSpacer size="m" />

        <div style={{ overflowX: 'auto' }}>
          <EuiInMemoryTable
            itemId="id"
            items={sortedHashRules}
            columns={hashColumns as any}
            loading={isLoading}
            pagination={false}
            sorting={false}
          />
        </div>

        {/* Add hashes flyout */}
        {drawerOpen === 'hashes' && (
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="s" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Add Custom Hash Content</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Name">
                    <EuiFieldText value={hashFormName} onChange={(e) => setHashFormName(e.target.value)} placeholder="rule name" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 180 }}>
                  <EuiFormRow label="Severity">
                    <EuiSelect options={severityOptions} value={hashFormSeverity} onChange={(e) => setHashFormSeverity(e.target.value)} />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiFormRow label="Tags (comma-separated)">
                <EuiFieldText value={hashFormTags} onChange={(e) => setHashFormTags(e.target.value)} placeholder="malware, custom" />
              </EuiFormRow>
              <EuiSpacer size="m" />
              <EuiFormRow label="Hash Content (one per line)">
                <EuiTextArea
                  value={hashFormContent}
                  onChange={(e) => setHashFormContent(e.target.value)}
                  placeholder={'sha256:6f2af3f7d9da2e9b9841c843f4f89d8f22d3a3f75cc9e70b2dd76378905c37da\nmd5:d41d8cd98f00b204e9800998ecf8427e'}
                  style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', minHeight: 120 }}
                />
              </EuiFormRow>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty onClick={() => setDrawerOpen('none')}>Cancel</EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      try {
                        await http.post('/api/xdr-defense/hashes/rules', {
                          body: JSON.stringify({
                            name: hashFormName,
                            content: hashFormContent,
                            severity: hashFormSeverity,
                            tags: hashFormTags.split(',').map((t) => t.trim()).filter((t) => t.length > 0),
                          }),
                        });
                        setDrawerOpen('none');
                        setHashFormName('');
                        setHashFormContent('');
                        setHashFormSeverity('medium');
                        setHashFormTags('');
                        await refreshHashRules();
                        setBanner({ kind: 'success', message: 'Custom hash content added.' });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to add hash content: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Add Hashes
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutFooter>
          </EuiFlyout>
        )}

        {/* MalwareBazaar config flyout */}
        {drawerOpen === 'malwarebazaar-config' && (
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="s" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Configure MalwareBazaar API Key</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiText size="s" color="subdued">
                <p>The key is shown only at entry time. Saving a new value overwrites the existing encrypted key in xdr-defense storage.</p>
              </EuiText>
              <EuiSpacer size="m" />
              <EuiFormRow label="MalwareBazaar API Key">
                <EuiFieldText
                  type="password"
                  value={malwareBazaarApiKey}
                  onChange={(e) => setMalwareBazaarApiKey(e.target.value)}
                  placeholder="Paste MalwareBazaar Auth-Key value"
                />
              </EuiFormRow>
              <EuiSpacer size="s" />
              <EuiText size="xs" color="subdued">
                <p>{status?.api_key_updated_at ? `Last updated ${new Date(status.api_key_updated_at).toLocaleString()}` : 'No key saved yet.'}</p>
              </EuiText>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty onClick={() => setDrawerOpen('none')}>Cancel</EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      try {
                        await http.post('/api/xdr-defense/hashes/malwarebazaar/config', {
                          body: JSON.stringify({ api_key: malwareBazaarApiKey }),
                        });
                        setMalwareBazaarApiKey('');
                        setDrawerOpen('none');
                        await refreshMalwareBazaarStatus();
                        notifications.toasts.addSuccess('MalwareBazaar API key saved. Future syncs will use the new key.');
                        setBanner({ kind: 'success', message: 'MalwareBazaar API key saved and stored in encrypted plugin state.' });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to save MalwareBazaar API key', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Failed to save MalwareBazaar API key: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Save Key
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutFooter>
          </EuiFlyout>
        )}
      </>
    );
  };

  const renderBehavioralTab = () => {
    const sortedRules = behavioralRules.slice().sort((a, b) => a.name.localeCompare(b.name));

    return (
      <>
        <EuiPanel>
          <EuiFlexGroup justifyContent="spaceBetween" alignItems="flexStart" wrap>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s"><h3>Behavioral Rule Registry</h3></EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued">
                <p>Maintain Sigma-style detection content with the same lifecycle controls as YARA and hashes.</p>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s">
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/behavioral/open-source/sync', {
                          body: JSON.stringify({}),
                        })) as { parallel_workers: number; imported: number; unchanged: number; load_failures: number; errors: string[] };
                        await refreshBehavioralRules();
                        await refreshYaraRules();
                        const errorText = Array.isArray(result.errors) && result.errors.length > 0 ? `\nErrors:\n${result.errors.join('\n')}` : '';
                        setBanner({
                          kind: 'success',
                          message: `SigmaHQ sync completed with ${result.parallel_workers} workers. Imported ${result.imported}, unchanged ${result.unchanged}, load failures ${result.load_failures}.${errorText}`,
                        });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to sync SigmaHQ rules: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Sync SigmaHQ Rules
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton onClick={() => setDrawerOpen('behavioral')}>Add Custom Behavioral Rule</EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        <EuiSpacer size="m" />

        <div style={{ overflowX: 'auto' }}>
          <EuiInMemoryTable
            itemId="id"
            items={sortedRules}
            columns={behavioralColumns as any}
            loading={isLoading}
            pagination={false}
            sorting={false}
          />
        </div>

        {/* Add behavioral flyout */}
        {drawerOpen === 'behavioral' && (
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="s" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Add Custom Behavioral Rule</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Name">
                    <EuiFieldText value={behavioralFormName} onChange={(e) => setBehavioralFormName(e.target.value)} placeholder="rule name" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 180 }}>
                  <EuiFormRow label="Severity">
                    <EuiSelect options={severityOptions} value={behavioralFormSeverity} onChange={(e) => setBehavioralFormSeverity(e.target.value)} />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiFormRow label="Tags (comma-separated)">
                <EuiFieldText value={behavioralFormTags} onChange={(e) => setBehavioralFormTags(e.target.value)} placeholder="malware, custom" />
              </EuiFormRow>
              <EuiSpacer size="m" />
              <EuiFormRow label="Rule Content (Sigma YAML)">
                <EuiTextArea
                  value={behavioralFormContent}
                  onChange={(e) => setBehavioralFormContent(e.target.value)}
                  placeholder={'title: Suspicious Process Pattern\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: "-EncodedCommand"\n  condition: selection'}
                  style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', minHeight: 120 }}
                />
              </EuiFormRow>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty onClick={() => setDrawerOpen('none')}>Cancel</EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      try {
                        await http.post('/api/xdr-defense/behavioral/rules', {
                          body: JSON.stringify({
                            name: behavioralFormName,
                            content: behavioralFormContent,
                            severity: behavioralFormSeverity,
                            tags: behavioralFormTags.split(',').map((t) => t.trim()).filter((t) => t.length > 0),
                          }),
                        });
                        setDrawerOpen('none');
                        setBehavioralFormName('');
                        setBehavioralFormContent('');
                        setBehavioralFormSeverity('medium');
                        setBehavioralFormTags('');
                        await refreshBehavioralRules();
                        setBanner({ kind: 'success', message: 'Custom behavioral rule added.' });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to add behavioral rule: ${String((err as Error)?.message ?? err)}` });
                      }
                    }}
                  >
                    Add Rule
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutFooter>
          </EuiFlyout>
        )}
      </>
    );
  };

  const renderBundleStatusTab = () => {
    if (!bundleMetadata) {
      return (
        <>
          <EuiPanel>
            <EuiTitle size="s"><h3>Bundle Status &amp; Rollout</h3></EuiTitle>
            <EuiSpacer size="s" />
            <EuiText><p><strong>Current Status:</strong> No YARA bundle generated yet.</p></EuiText>
            <EuiText><p>After adding or syncing YARA rules, build and sign a bundle for agent consumption.</p></EuiText>
          </EuiPanel>
          <EuiSpacer size="m" />
          <EuiButton
            fill
            onClick={async () => {
              setBanner(null);
              try {
                const response = (await http.post('/api/xdr-defense/yara/bundle/build', {
                  body: JSON.stringify({ policy_id: 'global-default' }),
                })) as SignedBundle | { bundle?: SignedBundle };
                const bundle = (response as { bundle?: SignedBundle }).bundle ?? (response as SignedBundle);
                setBanner({ kind: 'success', message: `Bundle built and signed: version ${bundle.bundle_version}` });
                await refreshBundleMetadata();
              } catch (err: unknown) {
                setBanner({ kind: 'error', message: `Failed to build bundle: ${String((err as Error)?.message ?? err)}` });
              }
            }}
          >
            Build &amp; Sign Bundle
          </EuiButton>
        </>
      );
    }

    return (
      <>
        <EuiTitle size="s"><h3>Bundle Status &amp; Rollout</h3></EuiTitle>
        <EuiSpacer size="m" />
        <EuiFlexGroup wrap>
          {[
            { label: 'Bundle Version', value: String(bundleMetadata.bundle_version) },
            { label: 'Generated', value: new Date(bundleMetadata.generated_at).toLocaleString() },
            { label: 'Total Rules', value: String(bundleMetadata.rule_count) },
            { label: 'Enabled Rules', value: String(bundleMetadata.enabled_rule_count) },
          ].map(({ label, value }) => (
            <EuiFlexItem key={label} style={{ minWidth: 160 }}>
              <EuiPanel color="subdued" paddingSize="s">
                <EuiText size="xs" color="subdued"><p>{label}</p></EuiText>
                <EuiText size="m"><p><strong>{value}</strong></p></EuiText>
              </EuiPanel>
            </EuiFlexItem>
          ))}
        </EuiFlexGroup>
        <EuiSpacer size="m" />
        <EuiPanel>
          <EuiText size="s"><p><strong>Policy ID:</strong> {bundleMetadata.policy_id}</p></EuiText>
          <EuiText size="s"><p><strong>Active Checksums:</strong> {bundleMetadata.active_checksums.length} rules signed</p></EuiText>
          {bundleMetadata.activated_at && (
            <EuiText size="s"><p><strong>Activated:</strong> {new Date(bundleMetadata.activated_at).toLocaleString()}</p></EuiText>
          )}
        </EuiPanel>
        <EuiSpacer size="m" />
        <EuiFlexGroup gutterSize="s">
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              onClick={async () => {
                setBanner(null);
                try {
                  const response = (await http.post('/api/xdr-defense/yara/bundle/build', {
                    body: JSON.stringify({ policy_id: 'global-default' }),
                  })) as SignedBundle | { bundle?: SignedBundle };
                  const bundle = (response as { bundle?: SignedBundle }).bundle ?? (response as SignedBundle);
                  setBanner({ kind: 'success', message: `Bundle rebuilt and signed: version ${bundle.bundle_version}` });
                  await refreshBundleMetadata();
                } catch (err: unknown) {
                  setBanner({ kind: 'error', message: `Failed to build bundle: ${String((err as Error)?.message ?? err)}` });
                }
              }}
            >
              Rebuild Bundle
            </EuiButton>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              onClick={async () => {
                setBanner(null);
                try {
                  const result = (await http.get('/api/xdr-defense/yara/bundle?policy_id=global-default')) as SignedBundle;
                  const manifest = {
                    manifest_version: result.manifest_version,
                    policy_id: result.policy_id,
                    bundle_version: result.bundle_version,
                    generated_at: result.generated_at,
                    signing_alg: result.signing_alg,
                    rule_count: result.rules.length,
                    active_checksums: result.active_checksums,
                  };
                  setBanner({ kind: 'success', message: `Bundle manifest:\n${JSON.stringify(manifest, null, 2)}` });
                } catch (err: unknown) {
                  setBanner({ kind: 'error', message: `Failed to view bundle: ${String((err as Error)?.message ?? err)}` });
                }
              }}
            >
              View Manifest
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </>
    );
  };

  const renderTestingTab = () => (
    <>
      <EuiTitle size="s"><h3>YARA Testing</h3></EuiTitle>
      <EuiSpacer size="m" />
      <EuiFlexGroup alignItems="flexStart">
        <EuiFlexItem>
          <EuiFormRow label="Sample Text (optional)">
            <EuiFieldText
              value={testSampleText}
              onChange={(e) => setTestSampleText(e.target.value)}
              placeholder="string to match in recent docs"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false} style={{ width: 180 }}>
          <EuiFormRow label="Lookback Minutes">
            <EuiFieldText
              type="number"
              value={testLookback}
              onChange={(e) => setTestLookback(e.target.value)}
              min="1"
              max="10080"
            />
          </EuiFormRow>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="m" />
      <EuiFormRow label="Rule Content">
        <EuiTextArea
          value={testContent}
          onChange={(e) => setTestContent(e.target.value)}
          placeholder="rule test_rule { ... }"
          style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', minHeight: 120 }}
        />
      </EuiFormRow>
      <EuiSpacer size="m" />
      <EuiButton
        fill
        onClick={async () => {
          setBanner(null);
          try {
            const result = (await http.post('/api/xdr-defense/yara/test', {
              body: JSON.stringify({
                content: testContent,
                sample_text: testSampleText,
                lookback_minutes: Number(testLookback || '60'),
              }),
            })) as YaraTestResponse;
            setTestOutput(JSON.stringify(result, null, 2));
          } catch (err: unknown) {
            setTestOutput(`Test failed: ${String((err as Error)?.message ?? err)}`);
          }
        }}
      >
        Run Test
      </EuiButton>
      <EuiSpacer size="m" />
      <EuiCodeBlock language="json" isCopyable paddingSize="m">
        {testOutput}
      </EuiCodeBlock>
    </>
  );

  const renderCorrelationTab = () => (
    <EuiPanel>
      <EuiTitle size="s"><h3>Correlation UX</h3></EuiTitle>
      <EuiSpacer size="s" />
      <EuiText>
        <p><strong>Status:</strong> agent handles single-event detections; OpenSearch handles time-window correlation.</p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiText>
        <p><strong>Guidance:</strong> keep signatures deterministic and aggregate suspicious patterns in OpenSearch correlation rules by host, process ancestry, and user context.</p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiText color="subdued" size="s"><p>No heavy backend work is wired for this tab yet.</p></EuiText>
    </EuiPanel>
  );

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div style={{ padding: 24, maxWidth: 1600 }}>
      <EuiTitle size="l"><h1>XDR Defense</h1></EuiTitle>
      <EuiText color="subdued" size="s">
        <p>Detection content, policy rollout, and artifact management for protected endpoints.</p>
      </EuiText>

      <EuiSpacer size="m" />

      {isLoading && !yaraRules.length && !hashRules.length && (
        <>
          <EuiLoadingSpinner size="m" />
          <EuiSpacer size="m" />
        </>
      )}

      {banner && (
        <>
          <EuiCallOut
            color={banner.kind === 'success' ? 'success' : 'danger'}
            title={<span style={{ whiteSpace: 'pre-wrap' }}>{banner.message}</span>}
          />
          <EuiSpacer size="m" />
        </>
      )}

      <EuiTabs>
        {[
          { id: 'detection-content', label: 'Yara' },
          { id: 'hashes', label: 'Hashes' },
          { id: 'behavioral-rules', label: 'Behavioral Rules' },
          { id: 'bundle-status', label: 'Bundle Status' },
          { id: 'testing', label: 'Testing' },
          { id: 'correlation-ux', label: 'Correlation UX' },
        ].map(({ id, label }) => (
          <EuiTab key={id} isSelected={activeTab === id} onClick={() => setActiveTab(id)}>
            {label}
          </EuiTab>
        ))}
      </EuiTabs>

      <EuiSpacer size="m" />

      {activeTab === 'detection-content' && renderYaraTab()}
      {activeTab === 'hashes' && renderHashesTab()}
      {activeTab === 'behavioral-rules' && renderBehavioralTab()}
      {activeTab === 'bundle-status' && renderBundleStatusTab()}
      {activeTab === 'testing' && renderTestingTab()}
      {activeTab === 'correlation-ux' && renderCorrelationTab()}
    </div>
  );
};
