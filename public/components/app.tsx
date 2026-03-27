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
  EuiFieldNumber,
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
  sha256_hash?: string;
  md5_hash?: string;
  sha1_hash?: string;
  file_name?: string;
  signature?: string;
  reporter?: string;
}

interface RulesResponse {
  rules: ManagedRule[];
  page?: number;
  pageSize?: number;
  total?: number;
  totalPages?: number;
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
  status?: 'idle' | 'processing' | 'completed' | 'failed';
  phase?: 'idle' | 'requesting_export' | 'preparing_download' | 'downloading' | 'importing' | 'completed' | 'failed';
  mode?: 'malwarebazaar_api' | 'daily_full_csv';
  message?: string;
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
  attempted?: number;
  imported?: number;
  unchanged?: number;
  load_failures?: number;
  last_error?: string;
}

interface HashRolloutResponse {
  started?: boolean;
  success?: boolean;
  message?: string;
  dateVersion?: string;
  bundle_version?: number;
  generated_at?: string;
  rule_count?: number;
  total_critical_hashes?: number;
}

interface HashRolloutStatusRow {
  agent: string;
  policy: string;
  state: string;
  full_bundle_version?: number;
  custom_bundle_version?: number;
  last_reported?: string;
  error?: string;
}

interface HashRolloutStatusPageResponse {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  stale_after_minutes: number;
  items: HashRolloutStatusRow[];
}

interface HashRolloutRetryResponse {
  success: boolean;
  message: string;
  overlay_bundle_version: number;
  pending_custom_entries: number;
  generated_at: string;
}

interface HashFormState {
  name: string;
  enabled: boolean;
  severity: string;
  tags: string;
  sha256_hash: string;
  md5_hash: string;
  sha1_hash: string;
  reporter: string;
  file_name: string;
  file_type_guess: string;
  mime_type: string;
  signature: string;
  clamav: string;
  vtpercent: string;
  imphash: string;
  ssdeep: string;
  tlsh: string;
}

type HashFormErrors = Partial<Record<keyof HashFormState, string>>;
type HashTextField = Exclude<keyof HashFormState, 'enabled'>;

const createEmptyHashForm = (): HashFormState => ({
  name: '',
  enabled: true,
  severity: 'medium',
  tags: '',
  sha256_hash: '',
  md5_hash: '',
  sha1_hash: '',
  reporter: '',
  file_name: '',
  file_type_guess: '',
  mime_type: '',
  signature: '',
  clamav: '',
  vtpercent: '',
  imphash: '',
  ssdeep: '',
  tlsh: '',
});

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
  const [hashRolloutRows, setHashRolloutRows] = useState<HashRolloutStatusRow[]>([]);
  const [hashRolloutTotal, setHashRolloutTotal] = useState(0);
  const [hashRolloutTotalPages, setHashRolloutTotalPages] = useState(1);
  const [hashRolloutStaleAfterMinutes, setHashRolloutStaleAfterMinutes] = useState(30);
  const [behavioralRules, setBehavioralRules] = useState<ManagedRule[]>([]);
  const [bundleMetadata, setBundleMetadata] = useState<BundleMetadata | null>(null);
  const [rolloutStatus, setRolloutStatus] = useState<RolloutStatusResponse | null>(null);
  const [yaraForgeSyncStatus, setYaraForgeSyncStatus] = useState<ForgeCoreSyncMetadata | null>(null);
  const [isSyncingYaraForge, setIsSyncingYaraForge] = useState(false);
  const [malwareBazaarStatus, setMalwareBazaarStatus] = useState<MalwareBazaarStatus | null>(null);
  const [isSyncingMalwareBazaar, setIsSyncingMalwareBazaar] = useState(false);
  const [isRollingOutHashes, setIsRollingOutHashes] = useState(false);
  const [isRetryingHashRollout, setIsRetryingHashRollout] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // ---- UI state ----
  const [drawerOpen, setDrawerOpen] = useState<'none' | 'yara' | 'hashes' | 'behavioral' | 'malwarebazaar-config'>('none');
  const [banner, setBanner] = useState<{ kind: 'success' | 'error' | 'warning'; message: string } | null>(null);

  // ---- YARA pagination / search / selection ----
  const [yaraSearchQuery, setYaraSearchQuery] = useState('');
  const [yaraPageSize, setYaraPageSize] = useState(20);
  const [yaraPageIndex, setYaraPageIndex] = useState(0);
  const [selectedYaraIds, setSelectedYaraIds] = useState<Set<string>>(new Set());
  const [isYaraBusy, setIsYaraBusy] = useState(false);

  // ---- Hashes pagination / search / selection ----
  const [hashRolloutPageSize, setHashRolloutPageSize] = useState(20);
  const [hashRolloutPageIndex, setHashRolloutPageIndex] = useState(0);

  // ---- YARA form ----
  const [yaraFormName, setYaraFormName] = useState('');
  const [yaraFormContent, setYaraFormContent] = useState('');
  const [yaraFormSeverity, setYaraFormSeverity] = useState('medium');
  const [yaraFormTags, setYaraFormTags] = useState('');

  // ---- Hash form ----
  const [hashForm, setHashForm] = useState<HashFormState>(createEmptyHashForm());
  const [hashFormErrors, setHashFormErrors] = useState<HashFormErrors>({});
  const [malwareBazaarApiKey, setMalwareBazaarApiKey] = useState('');
  const [mbAutoUpdateEnabled, setMbAutoUpdateEnabled] = useState(false);
  const [mbRequestsPerDayInput, setMbRequestsPerDayInput] = useState('1000');
  const [mbCallsPerWindow, setMbCallsPerWindow] = useState(3);
  const [mbSettingsSaving, setMbSettingsSaving] = useState(false);
  const [mbSyncNowRunning, setMbSyncNowRunning] = useState(false);

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

  const validateCustomHashForm = useCallback((form: HashFormState): HashFormErrors => {
    const errors: HashFormErrors = {};
    const sha256 = form.sha256_hash.trim();
    const md5 = form.md5_hash.trim();
    const sha1 = form.sha1_hash.trim();
    const imphash = form.imphash.trim();

    if (!sha256 && !md5 && !sha1) {
      const message = 'Provide at least one hash value.';
      errors.sha256_hash = message;
      errors.md5_hash = message;
      errors.sha1_hash = message;
    }

    if (sha256 && !/^[a-fA-F0-9]{64}$/.test(sha256)) {
      errors.sha256_hash = 'SHA256 must be exactly 64 hexadecimal characters.';
    }
    if (md5 && !/^[a-fA-F0-9]{32}$/.test(md5)) {
      errors.md5_hash = 'MD5 must be exactly 32 hexadecimal characters.';
    }
    if (sha1 && !/^[a-fA-F0-9]{40}$/.test(sha1)) {
      errors.sha1_hash = 'SHA1 must be exactly 40 hexadecimal characters.';
    }
    if (imphash && !/^[a-fA-F0-9]{32}$/.test(imphash)) {
      errors.imphash = 'imphash must be exactly 32 hexadecimal characters.';
    }

    return errors;
  }, []);

  const parseHashFieldErrors = useCallback((err: unknown): HashFormErrors => {
    const errorBody = ((err as any)?.body?.attributes?.body ?? (err as any)?.body ?? {}) as any;
    const rawFieldErrors = (errorBody?.field_errors ?? {}) as Record<string, unknown>;
    const parsed: HashFormErrors = {};

    for (const [field, value] of Object.entries(rawFieldErrors)) {
      const message = Array.isArray(value)
        ? value.map((entry) => String(entry)).join(' ')
        : String(value);
      if (!message) {
        continue;
      }
      if (field in createEmptyHashForm()) {
        parsed[field as keyof HashFormState] = message;
      }
    }

    return parsed;
  }, []);

  const customHashErrorMessage = useCallback((err: unknown): string => {
    const errorBody = ((err as any)?.body?.attributes?.body ?? (err as any)?.body ?? {}) as any;
    const bodyMessage = String(errorBody?.message ?? '').trim();
    if (bodyMessage) {
      return bodyMessage;
    }
    return String((err as Error)?.message ?? err);
  }, []);

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
      const params = new URLSearchParams();
      params.set('page', '1');
      params.set('pageSize', '20');
      const payload = (await http.get(`/api/xdr-defense/hashes/rules?${params.toString()}`)) as RulesResponse;
      setHashRules(Array.isArray(payload?.rules) ? payload.rules : []);
    } catch (err: unknown) {
      const statusCode = Number((err as any)?.body?.statusCode ?? (err as any)?.statusCode ?? 0);
      if (statusCode === 404) {
        // On fresh startup/reload windows, the route can briefly return Not Found.
        // Treat this as an empty state instead of showing a blocking error banner.
        setHashRules([]);
        return;
      }
      setBanner({ kind: 'error', message: `Failed to load hash rules: ${String((err as Error)?.message ?? err)}` });
    }
  }, [http]);

  const refreshHashRolloutStatus = useCallback(async (input?: { pageIndex?: number; pageSize?: number }) => {
    try {
      const pageIndex = input?.pageIndex ?? hashRolloutPageIndex;
      const pageSize = input?.pageSize ?? hashRolloutPageSize;
      const params = new URLSearchParams();
      params.set('page', String(pageIndex + 1));
      params.set('pageSize', String(pageSize));
      const payload = (await http.get(`/api/xdr-defense/hashes/rollouts/status?${params.toString()}`)) as HashRolloutStatusPageResponse;
      setHashRolloutRows(Array.isArray(payload?.items) ? payload.items : []);
      setHashRolloutTotal(Number(payload?.total ?? 0));
      setHashRolloutTotalPages(Math.max(1, Number(payload?.totalPages ?? 1)));
      setHashRolloutStaleAfterMinutes(Number(payload?.stale_after_minutes ?? 30));
    } catch {
      setHashRolloutRows([]);
      setHashRolloutTotal(0);
      setHashRolloutTotalPages(1);
    }
  }, [http, hashRolloutPageIndex, hashRolloutPageSize]);

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
      setIsSyncingMalwareBazaar(payload?.status === 'processing');
    } catch {
      setMalwareBazaarStatus(null);
      setIsSyncingMalwareBazaar(false);
    }
  }, [http]);

  const loadMbAutoUpdateSettings = useCallback(async () => {
    try {
      const data = (await http.get('/api/xdr-defense/hashes/malwarebazaar/auto-update-settings')) as {
        enabled: boolean;
        requests_per_day: number;
        calls_per_window: number;
      };
      setMbAutoUpdateEnabled(Boolean(data?.enabled));
      const requestsPerDay = Number(data?.requests_per_day) || 1000;
      setMbRequestsPerDayInput(String(requestsPerDay));
      setMbCallsPerWindow(Number(data?.calls_per_window) ?? 3);
    } catch {
      // use defaults on error
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
      refreshHashRolloutStatus(),
    ]);
  }, [refreshYaraRules, refreshHashRules, refreshBehavioralRules, refreshBundleMetadata, refreshRolloutStatus, refreshYaraForgeSyncStatus, refreshMalwareBazaarStatus, refreshHashRolloutStatus]);

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

  useEffect(() => {
    if (!isSyncingMalwareBazaar && malwareBazaarStatus?.status !== 'processing') {
      return;
    }

    const intervalId = window.setInterval(() => {
      refreshMalwareBazaarStatus();
    }, 750);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [isSyncingMalwareBazaar, malwareBazaarStatus?.status, refreshMalwareBazaarStatus]);

  useEffect(() => {
    refreshHashRolloutStatus();
  }, [hashRolloutPageIndex, hashRolloutPageSize, refreshHashRolloutStatus]);

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

  const hashRolloutColumns = [
    { field: 'agent', name: 'Agent' },
    { field: 'policy', name: 'Policy' },
    {
      field: 'state',
      name: 'State',
      render: (state: string) => (
        <EuiBadge
          color={
            state === 'applied'
              ? 'success'
              : state === 'pending'
                ? 'warning'
                : state === 'failed'
                  ? 'danger'
                  : 'hollow'
          }
        >
          {state}
        </EuiBadge>
      ),
    },
    {
      field: 'full_bundle_version',
      name: 'Full Bundle Version',
      render: (value?: number) => (value !== undefined ? String(value) : '-'),
    },
    {
      field: 'custom_bundle_version',
      name: 'Custom Bundle Version',
      render: (value?: number) => (value !== undefined ? String(value) : '-'),
    },
    {
      field: 'last_reported',
      name: 'Last Reported',
      render: (value?: string) => (value ? new Date(value).toLocaleString() : '-'),
    },
    {
      field: 'error',
      name: 'Error',
      render: (value?: string) => value || '-',
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
                  <EuiButtonEmpty
                    onClick={() => {
                      setHashFormErrors({});
                      setDrawerOpen('none');
                    }}
                  >
                    Cancel
                  </EuiButtonEmpty>
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
    const hashSyncing = isSyncingMalwareBazaar || status?.status === 'processing';
    const hashSyncBadgeColor =
      status?.status === 'failed'
        ? 'danger'
        : status?.status === 'completed'
          ? 'success'
          : status?.status === 'processing'
            ? 'warning'
            : 'hollow';
    const rolloutCurrentPage = Math.min(hashRolloutPageIndex, Math.max(0, hashRolloutTotalPages - 1));

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
                  <EuiBadge color={hashSyncBadgeColor}>sync {status?.status ?? 'idle'}</EuiBadge>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="xs" />
              <EuiText size="xs" color="subdued">
                <p>
                  {status?.last_successful_sync_at
                    ? `last sync ${new Date(status.last_successful_sync_at).toLocaleString()}`
                    : 'No successful MalwareBazaar sync yet.'}
                  {status?.last_total_hashes !== undefined ? ` · stored ${status.last_total_hashes}` : ''}
                  {status?.phase ? ` · phase ${status.phase}` : ''}
                </p>
              </EuiText>
              {status?.message && (
                <>
                  <EuiSpacer size="xs" />
                  <EuiText size="xs" color="subdued"><p>{status.message}</p></EuiText>
                </>
              )}
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" alignItems="center">
                <EuiFlexItem grow={false}>
                  <EuiButtonIcon
                    iconType="gear"
                    size="m"
                    aria-label="Configure MalwareBazaar API key"
                    onClick={() => {
                      setDrawerOpen('malwarebazaar-config');
                      loadMbAutoUpdateSettings();
                    }}
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    isDisabled={hashSyncing}
                    isLoading={hashSyncing}
                    onClick={async () => {
                      if (hashSyncing) return;
                      setIsSyncingMalwareBazaar(true);
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/hashes/malwarebazaar/full/sync', {
                          body: JSON.stringify({}),
                        })) as {
                          query_mode: string;
                          mode?: string;
                          upstream_records: number;
                          attempted?: number;
                          new_hashes: number;
                          total_hashes: number;
                          imported: number;
                          unchanged: number;
                          load_failures: number;
                          errors: string[];
                          started?: boolean;
                        };
                        await refreshMalwareBazaarStatus();
                        if (result.started) {
                          notifications.toasts.addSuccess('MalwareBazaar daily sync started.');
                          setBanner({
                            kind: 'success',
                            message: 'MalwareBazaar daily sync started. Progress will continue in the background.',
                          });
                        } else {
                          const errorText = Array.isArray(result.errors) && result.errors.length > 0 ? `\nErrors:\n${result.errors.join('\n')}` : '';
                          notifications.toasts.addSuccess(
                            `MalwareBazaar daily sync complete. Added ${result.new_hashes} new hashes.`
                          );
                          setBanner({
                            kind: 'success',
                            message: `MalwareBazaar daily sync completed. Attempted ${result.attempted ?? result.upstream_records}, imported ${result.imported}, unchanged ${result.unchanged}, load failures ${result.load_failures}, total stored ${result.total_hashes}.${errorText}`,
                          });
                        }
                      } catch (err: unknown) {
                        const statusCode = Number((err as any)?.body?.statusCode ?? (err as any)?.statusCode ?? 0);
                        if (statusCode === 409) {
                          await refreshMalwareBazaarStatus();
                          notifications.toasts.addWarning({ title: 'MalwareBazaar sync already running', text: 'Another MalwareBazaar sync is already in progress.' });
                          setBanner({ kind: 'warning', message: 'MalwareBazaar sync already running. The current sync will continue in the background.' });
                        } else {
                          notifications.toasts.addDanger({ title: 'Unable to sync MalwareBazaar daily hashes', text: (err as Error)?.message });
                          setBanner({ kind: 'error', message: `Failed to sync MalwareBazaar daily hashes: ${String((err as Error)?.message ?? err)}` });
                        }
                      } finally {
                        await refreshMalwareBazaarStatus();
                      }
                    }}
                  >
                    Sync MalwareBazaar Daily
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    onClick={() => {
                      setHashFormErrors({});
                      setHashForm(createEmptyHashForm());
                      setDrawerOpen('hashes');
                    }}
                  >
                    Add Custom Hashes
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={isRollingOutHashes}
                    isDisabled={isRollingOutHashes}
                    onClick={async () => {
                      if (isRollingOutHashes) return;
                      setIsRollingOutHashes(true);
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/hashes/rollout', {
                          body: JSON.stringify({ policy_id: 'global-default' }),
                        })) as HashRolloutResponse;
                        await refreshBundleMetadata();
                        await refreshMalwareBazaarStatus();
                        await refreshHashRolloutStatus();
                        const bundleVersion = result.bundle_version ?? 'n/a';
                        const ruleCount = result.rule_count ?? 0;
                        notifications.toasts.addSuccess(`Hash rollout triggered. Bundle version ${bundleVersion}, rules ${ruleCount}.`);
                        setBanner({
                          kind: 'success',
                          message: result.message
                            ? `${result.message} Bundle version ${bundleVersion}, rules ${ruleCount}.`
                            : `Hash rollout triggered. Bundle version ${bundleVersion}, rules ${ruleCount}.`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({
                          title: 'Unable to roll out hashes to all agents',
                          text: (err as Error)?.message,
                        });
                        setBanner({ kind: 'error', message: `Failed to roll out hashes to all agents: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        setIsRollingOutHashes(false);
                      }
                    }}
                  >
                    Rollout Hashes to All Agents
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={isRetryingHashRollout}
                    isDisabled={isRetryingHashRollout}
                    onClick={async () => {
                      if (isRetryingHashRollout) return;
                      setIsRetryingHashRollout(true);
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/hashes/rollouts/retry', {
                          body: JSON.stringify({}),
                        })) as HashRolloutRetryResponse;
                        await refreshHashRolloutStatus();
                        notifications.toasts.addSuccess('Hash rollout retry requested.');
                        setBanner({
                          kind: 'success',
                          message: `${result.message} Overlay version ${result.overlay_bundle_version}, pending custom entries ${result.pending_custom_entries}.`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({
                          title: 'Unable to retry hash rollout',
                          text: (err as Error)?.message,
                        });
                        setBanner({ kind: 'error', message: `Failed to retry hash rollout: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        setIsRetryingHashRollout(false);
                      }
                    }}
                  >
                    Retry Hash Rollout
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        <EuiSpacer size="m" />

        <EuiPanel>
          <EuiTitle size="s"><h3>Hash Rollout Status</h3></EuiTitle>
          <EuiSpacer size="s" />

          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
            <EuiFlexItem grow={false}>
              <EuiText size="s" color="subdued">
                <p>
                  Agent rollout state is based on per-agent reports. Agents without recent reports are marked
                  offline/unknown (stale after {hashRolloutStaleAfterMinutes} minutes).
                </p>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="xs"
                onClick={async () => {
                  await refreshMalwareBazaarStatus();
                  await refreshHashRolloutStatus();
                }}
              >
                Refresh Rollout Status
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '55vh' }}>
            <div style={{ display: 'inline-block', minWidth: 1400 }}>
              <EuiInMemoryTable
                itemId={(row: HashRolloutStatusRow) => `${row.agent}-${row.policy}`}
                items={hashRolloutRows}
                columns={hashRolloutColumns as any}
                loading={isLoading}
                pagination={false}
                sorting={false}
              />
            </div>
          </div>

          <EuiSpacer size="s" />

          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiText size="s"><span>Rows per page</span></EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiSelect
                    compressed
                      value={String(hashRolloutPageSize)}
                    onChange={(e) => {
                        setHashRolloutPageSize(Number(e.target.value));
                        setHashRolloutPageIndex(0);
                    }}
                    options={pageSizeOptions.map((o) => ({ value: String(o.value), text: o.text }))}
                  />
                </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiText size="s" color="subdued"><span>{hashRolloutTotal} agent entries</span></EuiText>
                  </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiPagination
                  pageCount={hashRolloutTotalPages}
                  activePage={rolloutCurrentPage}
                  onPageClick={setHashRolloutPageIndex}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        {/* Add hashes flyout */}
        {drawerOpen === 'hashes' && (
          <EuiFlyout
            onClose={() => {
              setHashFormErrors({});
              setDrawerOpen('none');
            }}
            size="s"
            ownFocus
          >
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Add Custom Hash</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiCallOut size="s" title="Stored in .xdr-defense-hashes with source=custom">
                <p>After saving a custom hash, click Rollout Hashes to All Agents to publish the refreshed hash bundle immediately.</p>
              </EuiCallOut>
              <EuiSpacer size="m" />
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Name">
                    <EuiFieldText value={hashForm.name} onChange={(e) => setHashForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="Custom malware hash" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 180 }}>
                  <EuiFormRow label="Severity">
                    <EuiSelect options={severityOptions} value={hashForm.severity} onChange={(e) => setHashForm((prev) => ({ ...prev, severity: e.target.value }))} />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiFlexGroup>
                <EuiFlexItem grow={false}>
                  <EuiSwitch
                    label="Enabled"
                    checked={hashForm.enabled}
                    onChange={(e) => setHashForm((prev) => ({ ...prev, enabled: e.target.checked }))}
                  />
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label="Tags (comma-separated)">
                    <EuiFieldText value={hashForm.tags} onChange={(e) => setHashForm((prev) => ({ ...prev, tags: e.target.value }))} placeholder="malware, custom" />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiTitle size="xs"><h3>Hash Values</h3></EuiTitle>
              <EuiSpacer size="s" />
              <EuiFormRow
                label="SHA256"
                isInvalid={Boolean(hashFormErrors.sha256_hash)}
                error={hashFormErrors.sha256_hash ? [hashFormErrors.sha256_hash] : undefined}
              >
                <EuiFieldText
                  isInvalid={Boolean(hashFormErrors.sha256_hash)}
                  value={hashForm.sha256_hash}
                  onChange={(e) => {
                    const value = e.target.value;
                    setHashForm((prev) => ({ ...prev, sha256_hash: value }));
                    setHashFormErrors((prev) => {
                      const next = { ...prev };
                      delete next.sha256_hash;
                      return next;
                    });
                  }}
                  placeholder="64 hex characters"
                />
              </EuiFormRow>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow
                    label="MD5"
                    isInvalid={Boolean(hashFormErrors.md5_hash)}
                    error={hashFormErrors.md5_hash ? [hashFormErrors.md5_hash] : undefined}
                  >
                    <EuiFieldText
                      isInvalid={Boolean(hashFormErrors.md5_hash)}
                      value={hashForm.md5_hash}
                      onChange={(e) => {
                        const value = e.target.value;
                        setHashForm((prev) => ({ ...prev, md5_hash: value }));
                        setHashFormErrors((prev) => {
                          const next = { ...prev };
                          delete next.md5_hash;
                          return next;
                        });
                      }}
                      placeholder="32 hex characters"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow
                    label="SHA1"
                    isInvalid={Boolean(hashFormErrors.sha1_hash)}
                    error={hashFormErrors.sha1_hash ? [hashFormErrors.sha1_hash] : undefined}
                  >
                    <EuiFieldText
                      isInvalid={Boolean(hashFormErrors.sha1_hash)}
                      value={hashForm.sha1_hash}
                      onChange={(e) => {
                        const value = e.target.value;
                        setHashForm((prev) => ({ ...prev, sha1_hash: value }));
                        setHashFormErrors((prev) => {
                          const next = { ...prev };
                          delete next.sha1_hash;
                          return next;
                        });
                      }}
                      placeholder="40 hex characters"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiTitle size="xs"><h3>Metadata</h3></EuiTitle>
              <EuiSpacer size="s" />
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="File name">
                    <EuiFieldText value={hashForm.file_name} onChange={(e) => setHashForm((prev) => ({ ...prev, file_name: e.target.value }))} placeholder="sample.exe" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label="Signature">
                    <EuiFieldText value={hashForm.signature} onChange={(e) => setHashForm((prev) => ({ ...prev, signature: e.target.value }))} placeholder="Malware family / signature" />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Reporter">
                    <EuiFieldText value={hashForm.reporter} onChange={(e) => setHashForm((prev) => ({ ...prev, reporter: e.target.value }))} placeholder="Analyst or source" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label="File type guess">
                    <EuiFieldText value={hashForm.file_type_guess} onChange={(e) => setHashForm((prev) => ({ ...prev, file_type_guess: e.target.value }))} placeholder="exe / dll / script" />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="MIME type">
                    <EuiFieldText value={hashForm.mime_type} onChange={(e) => setHashForm((prev) => ({ ...prev, mime_type: e.target.value }))} placeholder="application/x-dosexec" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label="VT percent">
                    <EuiFieldText value={hashForm.vtpercent} onChange={(e) => setHashForm((prev) => ({ ...prev, vtpercent: e.target.value }))} placeholder="70" />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="ClamAV">
                    <EuiFieldText value={hashForm.clamav} onChange={(e) => setHashForm((prev) => ({ ...prev, clamav: e.target.value }))} placeholder="Win.Trojan.Sample" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow
                    label="imphash"
                    isInvalid={Boolean(hashFormErrors.imphash)}
                    error={hashFormErrors.imphash ? [hashFormErrors.imphash] : undefined}
                  >
                    <EuiFieldText
                      isInvalid={Boolean(hashFormErrors.imphash)}
                      value={hashForm.imphash}
                      onChange={(e) => {
                        const value = e.target.value;
                        setHashForm((prev) => ({ ...prev, imphash: value }));
                        setHashFormErrors((prev) => {
                          const next = { ...prev };
                          delete next.imphash;
                          return next;
                        });
                      }}
                      placeholder="32 hex characters"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="ssdeep">
                    <EuiFieldText value={hashForm.ssdeep} onChange={(e) => setHashForm((prev) => ({ ...prev, ssdeep: e.target.value }))} placeholder="ssdeep fuzzy hash" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label="TLSH">
                    <EuiFieldText value={hashForm.tlsh} onChange={(e) => setHashForm((prev) => ({ ...prev, tlsh: e.target.value }))} placeholder="T1..." />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty
                    onClick={() => {
                      setHashFormErrors({});
                      setDrawerOpen('none');
                    }}
                  >
                    Cancel
                  </EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      const localErrors = validateCustomHashForm(hashForm);
                      if (Object.keys(localErrors).length > 0) {
                        setHashFormErrors(localErrors);
                        return;
                      }

                      const payload: Record<string, unknown> = {
                        enabled: hashForm.enabled,
                        severity: hashForm.severity,
                        tags: hashForm.tags.split(',').map((t) => t.trim()).filter((t) => t.length > 0),
                      };

                      const assignOptionalTrimmed = (key: HashTextField) => {
                        const value = hashForm[key].trim();
                        if (value.length > 0) {
                          payload[key] = value;
                        }
                      };

                      assignOptionalTrimmed('name');
                      assignOptionalTrimmed('sha256_hash');
                      assignOptionalTrimmed('md5_hash');
                      assignOptionalTrimmed('sha1_hash');
                      assignOptionalTrimmed('reporter');
                      assignOptionalTrimmed('file_name');
                      assignOptionalTrimmed('file_type_guess');
                      assignOptionalTrimmed('mime_type');
                      assignOptionalTrimmed('signature');
                      assignOptionalTrimmed('clamav');
                      assignOptionalTrimmed('vtpercent');
                      assignOptionalTrimmed('imphash');
                      assignOptionalTrimmed('ssdeep');
                      assignOptionalTrimmed('tlsh');

                      try {
                        setHashFormErrors({});
                        await http.post('/api/xdr-defense/hashes/rules', {
                          body: JSON.stringify(payload),
                        });
                        setDrawerOpen('none');
                        setHashForm(createEmptyHashForm());
                        setHashFormErrors({});
                        await refreshHashRules();
                        setBanner({ kind: 'success', message: 'Custom hash saved to .xdr-defense-hashes.' });
                      } catch (err: unknown) {
                        const backendFieldErrors = parseHashFieldErrors(err);
                        if (Object.keys(backendFieldErrors).length > 0) {
                          setHashFormErrors(backendFieldErrors);
                        }
                        setBanner({ kind: 'error', message: `Failed to save custom hash: ${customHashErrorMessage(err)}` });
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
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="m" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>MalwareBazaar Configuration</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              {/* Section 1: API Key */}
              <EuiTitle size="s"><h3>MalwareBazaar API Key</h3></EuiTitle>
              <EuiSpacer size="s" />
              <EuiText size="s" color="subdued">
                <p>The key is shown only at entry time. Saving a new value overwrites the existing encrypted key in xdr-defense storage.</p>
              </EuiText>
              <EuiSpacer size="m" />
              <EuiFormRow label="API Key">
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
              <EuiSpacer size="s" />
              <EuiFlexGroup justifyContent="flexEnd">
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      try {
                        await http.post('/api/xdr-defense/hashes/malwarebazaar/config', {
                          body: JSON.stringify({ api_key: malwareBazaarApiKey }),
                        });
                        setMalwareBazaarApiKey('');
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

              <EuiHorizontalRule />

              {/* Section 2: Database Update via API */}
              <EuiTitle size="s"><h3>Database Update via API</h3></EuiTitle>
              <EuiSpacer size="s" />
              <EuiText size="s" color="subdued">
                <p>
                  Automatically enrich hash records that are missing VirusTotal data by querying MalwareBazaar.
                  The update targets the records that have no <strong>vtpercent</strong> value, starting with the oldest.
                  No bundle rollout to agents is triggered.
                </p>
              </EuiText>
              <EuiSpacer size="m" />
              <EuiFormRow label="Enable automatic updates">
                <EuiSwitch
                  label={mbAutoUpdateEnabled ? 'On' : 'Off'}
                  checked={mbAutoUpdateEnabled}
                  onChange={(e) => setMbAutoUpdateEnabled(e.target.checked)}
                />
              </EuiFormRow>
              <EuiSpacer size="m" />
              <EuiFormRow
                label="API requests per day"
                helpText={`= ${mbCallsPerWindow} API call${mbCallsPerWindow === 1 ? '' : 's'} per 5-minute window`}
              >
                <EuiFieldNumber
                  min={1}
                  max={100000}
                  value={mbRequestsPerDayInput}
                  onChange={(e) => {
                    const raw = e.target.value;
                    setMbRequestsPerDayInput(raw);
                    const parsed = Number(raw);
                    if (!Number.isFinite(parsed) || raw.trim() === '') {
                      setMbCallsPerWindow(0);
                      return;
                    }
                    const clamped = Math.max(1, Math.min(100000, Math.floor(parsed)));
                    setMbCallsPerWindow(Math.floor(clamped * 5 / (24 * 60)));
                  }}
                  onBlur={() => {
                    const parsed = Number(mbRequestsPerDayInput);
                    if (!Number.isFinite(parsed) || mbRequestsPerDayInput.trim() === '') {
                      setMbRequestsPerDayInput('1000');
                      setMbCallsPerWindow(Math.floor(1000 * 5 / (24 * 60)));
                      return;
                    }
                    const clamped = Math.max(1, Math.min(100000, Math.floor(parsed)));
                    setMbRequestsPerDayInput(String(clamped));
                    setMbCallsPerWindow(Math.floor(clamped * 5 / (24 * 60)));
                  }}
                />
              </EuiFormRow>
              <EuiSpacer size="m" />
              <EuiFlexGroup justifyContent="spaceBetween" alignItems="center">
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={mbSyncNowRunning}
                    onClick={async () => {
                      setMbSyncNowRunning(true);
                      try {
                        const result = (await http.post('/api/xdr-defense/hashes/malwarebazaar/auto-update-sync-now', {
                          body: JSON.stringify({}),
                        })) as {
                          attempted: number;
                          enriched: number;
                          message: string;
                        };
                        await refreshHashRules();
                        notifications.toasts.addSuccess(
                          result.attempted > 0
                            ? `Sync now completed. 1 lookup executed, ${result.enriched} document updated.`
                            : result.message
                        );
                        setBanner({
                          kind: 'success',
                          message:
                            result.attempted > 0
                              ? `Database Update via API sync-now completed. Lookups executed: ${result.attempted}, updated documents: ${result.enriched}.`
                              : result.message,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to run sync now', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Sync now failed: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        setMbSyncNowRunning(false);
                      }
                    }}
                  >
                    Sync Now
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    isLoading={mbSettingsSaving}
                    onClick={async () => {
                      const parsed = Number(mbRequestsPerDayInput);
                      if (!Number.isFinite(parsed) || mbRequestsPerDayInput.trim() === '') {
                        notifications.toasts.addDanger({
                          title: 'Invalid requests per day',
                          text: 'Enter a number between 1 and 100000 before saving.'
                        });
                        return;
                      }

                      const requestsPerDay = Math.max(1, Math.min(100000, Math.floor(parsed)));
                      setMbRequestsPerDayInput(String(requestsPerDay));
                      setMbCallsPerWindow(Math.floor(requestsPerDay * 5 / (24 * 60)));

                      setMbSettingsSaving(true);
                      try {
                        await http.post('/api/xdr-defense/hashes/malwarebazaar/auto-update-settings', {
                          body: JSON.stringify({
                            enabled: mbAutoUpdateEnabled,
                            requests_per_day: requestsPerDay
                          }),
                        });
                        notifications.toasts.addSuccess('Auto-update settings saved.');
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to save auto-update settings', text: (err as Error)?.message });
                      } finally {
                        setMbSettingsSaving(false);
                      }
                    }}
                  >
                    Save Settings
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiButtonEmpty onClick={() => setDrawerOpen('none')}>Close</EuiButtonEmpty>
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
            color={banner.kind === 'success' ? 'success' : banner.kind === 'warning' ? 'warning' : 'danger'}
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
