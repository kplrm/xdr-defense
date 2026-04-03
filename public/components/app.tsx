import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiCallOut,
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

interface YaraRolloutResponse {
  started?: boolean;
  success?: boolean;
  message?: string;
  policy_id?: string;
  bundle_version?: number;
  generated_at?: string;
  rule_count?: number;
  confirmation?: {
    target_agents: number;
    confirmed_agents: number;
    applied: number;
    partial: number;
    failed: number;
    pending: number;
    timed_out: boolean;
  };
}

interface YaraRolloutStatusRow {
  agent: string;
  policy: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  failed_rule_count?: number;
  last_reported?: string;
  error?: string;
}

interface YaraRolloutStatusPageResponse {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  stale_after_minutes: number;
  items: YaraRolloutStatusRow[];
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

interface ProtectionSyncResponse {
  imported: number;
  unchanged: number;
  attempted: number;
  source: string;
  source_name: string;
  index_name: string;
  upstream_total_rules: number;
  upstream_candidate_rules?: number;
  curated_rules: number;
  steps?: ProtectionSyncStep[];
  source_breakdown?: ProtectionSyncSourceBreakdown[];
}

interface ProtectionSyncStep {
  stage: string;
  message: string;
  at: string;
  details?: Record<string, unknown>;
}

interface ProtectionSyncSourceBreakdown {
  source: string;
  attempted: number;
  imported: number;
  unchanged: number;
}

interface ProtectionSyncJobStatus {
  job_id: string;
  namespace: 'memory' | 'ransomware';
  status: 'running' | 'completed' | 'failed';
  created_at: string;
  updated_at: string;
  completed_at?: string;
  steps: ProtectionSyncStep[];
  result?: ProtectionSyncResponse;
  error?: string;
}

interface ProtectionSyncJobStartResponse {
  started: boolean;
  already_running?: boolean;
  job: ProtectionSyncJobStatus;
}

interface ProtectionRolloutRow {
  agent: string;
  policy: string;
  state: string;
  bundle_version?: number;
  total_rules?: number;
  loaded_rules?: number;
  last_reported?: string;
  error?: string;
}

interface ProtectionRolloutPageResponse {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  stale_after_minutes: number;
  items: ProtectionRolloutRow[];
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
  const [yaraRolloutRows, setYaraRolloutRows] = useState<YaraRolloutStatusRow[]>([]);
  const [yaraRolloutTotal, setYaraRolloutTotal] = useState(0);
  const [yaraRolloutTotalPages, setYaraRolloutTotalPages] = useState(1);
  const [yaraRolloutStaleAfterMinutes, setYaraRolloutStaleAfterMinutes] = useState(30);
  const [hashRolloutRows, setHashRolloutRows] = useState<HashRolloutStatusRow[]>([]);
  const [hashRolloutTotal, setHashRolloutTotal] = useState(0);
  const [hashRolloutTotalPages, setHashRolloutTotalPages] = useState(1);
  const [hashRolloutStaleAfterMinutes, setHashRolloutStaleAfterMinutes] = useState(30);
  const [behavioralRules, setBehavioralRules] = useState<ManagedRule[]>([]);
  const [memoryRolloutRows, setMemoryRolloutRows] = useState<ProtectionRolloutRow[]>([]);
  const [memoryRolloutTotal, setMemoryRolloutTotal] = useState(0);
  const [memoryRolloutTotalPages, setMemoryRolloutTotalPages] = useState(1);
  const [memoryRolloutStaleAfterMinutes, setMemoryRolloutStaleAfterMinutes] = useState(30);
  const [ransomwareRolloutRows, setRansomwareRolloutRows] = useState<ProtectionRolloutRow[]>([]);
  const [ransomwareRolloutTotal, setRansomwareRolloutTotal] = useState(0);
  const [ransomwareRolloutTotalPages, setRansomwareRolloutTotalPages] = useState(1);
  const [ransomwareRolloutStaleAfterMinutes, setRansomwareRolloutStaleAfterMinutes] = useState(30);
  const [bundleMetadata, setBundleMetadata] = useState<BundleMetadata | null>(null);
  const [yaraForgeSyncStatus, setYaraForgeSyncStatus] = useState<ForgeCoreSyncMetadata | null>(null);
  const [isSyncingYaraForge, setIsSyncingYaraForge] = useState(false);
  const [malwareBazaarStatus, setMalwareBazaarStatus] = useState<MalwareBazaarStatus | null>(null);
  const [isSyncingMalwareBazaar, setIsSyncingMalwareBazaar] = useState(false);
  const [isRollingOutYara, setIsRollingOutYara] = useState(false);
  const [isRetryingYaraRollout, setIsRetryingYaraRollout] = useState(false);
  const [isRollingOutHashes, setIsRollingOutHashes] = useState(false);
  const [isRetryingHashRollout, setIsRetryingHashRollout] = useState(false);
  const [isSyncingMemorySource, setIsSyncingMemorySource] = useState(false);
  const [isSyncingRansomwareSource, setIsSyncingRansomwareSource] = useState(false);
  const [memorySyncSteps, setMemorySyncSteps] = useState<ProtectionSyncStep[]>([]);
  const [ransomwareSyncSteps, setRansomwareSyncSteps] = useState<ProtectionSyncStep[]>([]);
  const [memorySyncStatusText, setMemorySyncStatusText] = useState('Idle');
  const [ransomwareSyncStatusText, setRansomwareSyncStatusText] = useState('Idle');
  const [isRollingOutMemory, setIsRollingOutMemory] = useState(false);
  const [isRetryingMemoryRollout, setIsRetryingMemoryRollout] = useState(false);
  const [isRollingOutRansomware, setIsRollingOutRansomware] = useState(false);
  const [isRetryingRansomwareRollout, setIsRetryingRansomwareRollout] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // ---- UI state ----
  const [drawerOpen, setDrawerOpen] = useState<'none' | 'yara' | 'hashes' | 'behavioral' | 'malwarebazaar-config' | 'memory' | 'ransomware'>('none');
  const [banner, setBanner] = useState<{ kind: 'success' | 'error' | 'warning'; message: string } | null>(null);

  // ---- YARA rollout pagination ----
  const [yaraRolloutPageSize, setYaraRolloutPageSize] = useState(20);
  const [yaraRolloutPageIndex, setYaraRolloutPageIndex] = useState(0);

  // ---- Hashes pagination / search / selection ----
  const [hashRolloutPageSize, setHashRolloutPageSize] = useState(20);
  const [hashRolloutPageIndex, setHashRolloutPageIndex] = useState(0);
  const [memoryRolloutPageSize, setMemoryRolloutPageSize] = useState(20);
  const [memoryRolloutPageIndex, setMemoryRolloutPageIndex] = useState(0);
  const [ransomwareRolloutPageSize, setRansomwareRolloutPageSize] = useState(20);
  const [ransomwareRolloutPageIndex, setRansomwareRolloutPageIndex] = useState(0);

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
  const [memoryFormName, setMemoryFormName] = useState('');
  const [memoryFormContent, setMemoryFormContent] = useState('');
  const [memoryFormSeverity, setMemoryFormSeverity] = useState('medium');
  const [memoryFormTags, setMemoryFormTags] = useState('');
  const [ransomwareFormName, setRansomwareFormName] = useState('');
  const [ransomwareFormContent, setRansomwareFormContent] = useState('');
  const [ransomwareFormSeverity, setRansomwareFormSeverity] = useState('medium');
  const [ransomwareFormTags, setRansomwareFormTags] = useState('');

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

  const refreshMemoryRolloutStatus = useCallback(async (input?: { pageIndex?: number; pageSize?: number }) => {
    try {
      const pageIndex = input?.pageIndex ?? memoryRolloutPageIndex;
      const pageSize = input?.pageSize ?? memoryRolloutPageSize;
      const params = new URLSearchParams();
      params.set('page', String(pageIndex + 1));
      params.set('pageSize', String(pageSize));
      const payload = (await http.get(`/api/xdr-defense/memory/rollouts/status?${params.toString()}`)) as ProtectionRolloutPageResponse;
      setMemoryRolloutRows(Array.isArray(payload?.items) ? payload.items : []);
      setMemoryRolloutTotal(Number(payload?.total ?? 0));
      setMemoryRolloutTotalPages(Math.max(1, Number(payload?.totalPages ?? 1)));
      setMemoryRolloutStaleAfterMinutes(Number(payload?.stale_after_minutes ?? 30));
    } catch {
      setMemoryRolloutRows([]);
      setMemoryRolloutTotal(0);
      setMemoryRolloutTotalPages(1);
    }
  }, [http, memoryRolloutPageIndex, memoryRolloutPageSize]);

  const refreshRansomwareRolloutStatus = useCallback(async (input?: { pageIndex?: number; pageSize?: number }) => {
    try {
      const pageIndex = input?.pageIndex ?? ransomwareRolloutPageIndex;
      const pageSize = input?.pageSize ?? ransomwareRolloutPageSize;
      const params = new URLSearchParams();
      params.set('page', String(pageIndex + 1));
      params.set('pageSize', String(pageSize));
      const payload = (await http.get(`/api/xdr-defense/ransomware/rollouts/status?${params.toString()}`)) as ProtectionRolloutPageResponse;
      setRansomwareRolloutRows(Array.isArray(payload?.items) ? payload.items : []);
      setRansomwareRolloutTotal(Number(payload?.total ?? 0));
      setRansomwareRolloutTotalPages(Math.max(1, Number(payload?.totalPages ?? 1)));
      setRansomwareRolloutStaleAfterMinutes(Number(payload?.stale_after_minutes ?? 30));
    } catch {
      setRansomwareRolloutRows([]);
      setRansomwareRolloutTotal(0);
      setRansomwareRolloutTotalPages(1);
    }
  }, [http, ransomwareRolloutPageIndex, ransomwareRolloutPageSize]);

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

  const refreshYaraRolloutStatus = useCallback(async (input?: { pageIndex?: number; pageSize?: number }) => {
    try {
      const pageIndex = input?.pageIndex ?? yaraRolloutPageIndex;
      const pageSize = input?.pageSize ?? yaraRolloutPageSize;
      const params = new URLSearchParams();
      params.set('page', String(pageIndex + 1));
      params.set('pageSize', String(pageSize));
      const payload = (await http.get(`/api/xdr-defense/yara/rollouts/status?${params.toString()}`)) as YaraRolloutStatusPageResponse;
      setYaraRolloutRows(Array.isArray(payload?.items) ? payload.items : []);
      setYaraRolloutTotal(Number(payload?.total ?? 0));
      setYaraRolloutTotalPages(Math.max(1, Number(payload?.totalPages ?? 1)));
      setYaraRolloutStaleAfterMinutes(Number(payload?.stale_after_minutes ?? 30));
    } catch {
      setYaraRolloutRows([]);
      setYaraRolloutTotal(0);
      setYaraRolloutTotalPages(1);
    }
  }, [http, yaraRolloutPageIndex, yaraRolloutPageSize]);

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
      refreshYaraRolloutStatus(),
      refreshYaraForgeSyncStatus(),
      refreshMalwareBazaarStatus(),
      refreshHashRolloutStatus(),
      refreshMemoryRolloutStatus(),
      refreshRansomwareRolloutStatus(),
    ]);
  }, [refreshYaraRules, refreshHashRules, refreshBehavioralRules, refreshBundleMetadata, refreshYaraRolloutStatus, refreshYaraForgeSyncStatus, refreshMalwareBazaarStatus, refreshHashRolloutStatus, refreshMemoryRolloutStatus, refreshRansomwareRolloutStatus]);

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
    refreshYaraRolloutStatus();
  }, [yaraRolloutPageIndex, yaraRolloutPageSize, refreshYaraRolloutStatus]);

  useEffect(() => {
    refreshHashRolloutStatus();
  }, [hashRolloutPageIndex, hashRolloutPageSize, refreshHashRolloutStatus]);

  useEffect(() => {
    refreshMemoryRolloutStatus();
  }, [memoryRolloutPageIndex, memoryRolloutPageSize, refreshMemoryRolloutStatus]);

  useEffect(() => {
    refreshRansomwareRolloutStatus();
  }, [ransomwareRolloutPageIndex, ransomwareRolloutPageSize, refreshRansomwareRolloutStatus]);

  // ---------------------------------------------------------------------------
  // Rollout status columns
  // ---------------------------------------------------------------------------

  const yaraRolloutColumns = [
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
              : state === 'partial'
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
      field: 'bundle_version',
      name: 'Bundle Version',
      render: (value?: number) => (value !== undefined ? String(value) : '-'),
    },
    {
      field: 'loaded_rules',
      name: 'Loaded Rules',
      render: (_: number | undefined, row: YaraRolloutStatusRow) => {
        if (row.loaded_rules === undefined && row.total_rules === undefined) {
          return '-';
        }
        return `${row.loaded_rules ?? 0}/${row.total_rules ?? 0}`;
      },
    },
    {
      field: 'failed_rule_count',
      name: 'Failed Rules',
      render: (value?: number) => String(value ?? 0),
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

  const protectionRolloutColumns = [
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
      field: 'bundle_version',
      name: 'Bundle Version',
      render: (value?: number) => (value !== undefined ? String(value) : '-'),
    },
    {
      field: 'loaded_rules',
      name: 'Loaded Rules',
      render: (_: number | undefined, row: ProtectionRolloutRow) => {
        if (row.loaded_rules === undefined && row.total_rules === undefined) {
          return '-';
        }
        return `${row.loaded_rules ?? 0}/${row.total_rules ?? 0}`;
      },
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
    const activeCount = yaraRules.filter((r) => r.enabled).length;
    const invalidCount = yaraRules.filter((r) => r.validation.status === 'invalid').length;
    const syncMeta = yaraForgeSyncStatus;
    const rolloutCurrentPage = Math.min(yaraRolloutPageIndex, Math.max(0, yaraRolloutTotalPages - 1));

    return (
      <>
        <EuiPanel>
          <EuiFlexGroup justifyContent="spaceBetween" alignItems="flexStart" wrap>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s"><h3>YARA Content Registry</h3></EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued">
                <p>Sync YARA Forge Core into the persisted registry, build the signed cached bundle, and roll it out to agents on demand.</p>
              </EuiText>
              <EuiSpacer size="s" />
              <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
                <EuiFlexItem grow={false}><EuiBadge color="hollow">stored {yaraRules.length}</EuiBadge></EuiFlexItem>
                <EuiFlexItem grow={false}><EuiBadge color="default">enabled {activeCount}</EuiBadge></EuiFlexItem>
                <EuiFlexItem grow={false}><EuiBadge color={invalidCount > 0 ? 'danger' : 'success'}>invalid {invalidCount}</EuiBadge></EuiFlexItem>
                <EuiFlexItem grow={false}><EuiBadge color={syncBadgeColor}>sync {syncMeta?.status ?? 'idle'}</EuiBadge></EuiFlexItem>
                {bundleMetadata && (
                  <EuiFlexItem grow={false}><EuiBadge color="accent">bundle {bundleMetadata.bundle_version}</EuiBadge></EuiFlexItem>
                )}
              </EuiFlexGroup>
              <EuiSpacer size="xs" />
              <EuiText size="xs" color="subdued">
                <p>
                  {syncMeta?.started_at
                    ? `last sync started ${new Date(syncMeta.started_at).toLocaleString()}`
                    : 'No YARA Forge Core sync started yet.'}
                  {syncMeta?.completed_at ? ` · completed ${new Date(syncMeta.completed_at).toLocaleString()}` : ''}
                  {bundleMetadata?.generated_at ? ` · bundle generated ${new Date(bundleMetadata.generated_at).toLocaleString()}` : ''}
                </p>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
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
                          attempted: number;
                          loaded: number;
                          imported: number;
                          unchanged: number;
                          removed?: number;
                          load_failures: number;
                          metadata?: ForgeCoreSyncMetadata;
                          errors?: string[];
                        };
                        if (result.metadata) {
                          setYaraForgeSyncStatus(result.metadata);
                        }
                        await refreshAll();
                        const errorText = Array.isArray(result.errors) && result.errors.length > 0
                          ? ` Issues: ${result.errors.join(' | ')}`
                          : '';
                        notifications.toasts.addSuccess(
                          `YARA Forge Core sync ${result.status === 'running' ? 'already running' : 'completed'}.`
                        );
                        setBanner({
                          kind: 'success',
                          message: `YARA Forge Core sync ${result.status === 'running' ? 'already running' : 'completed'}. Attempted ${result.attempted}, loaded ${result.loaded}, imported ${result.imported}, unchanged ${result.unchanged}, removed ${result.removed ?? 0}, load failures ${result.load_failures}.${errorText}`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to sync YARA Forge Core', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Failed to sync YARA Forge Core: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        await refreshYaraForgeSyncStatus();
                        await refreshBundleMetadata();
                        await refreshYaraRolloutStatus();
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
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={isRollingOutYara}
                    isDisabled={isRollingOutYara}
                    onClick={async () => {
                      if (isRollingOutYara) return;
                      setIsRollingOutYara(true);
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/yara/rollout', {
                          body: JSON.stringify({ policy_id: 'global-default' }),
                        })) as YaraRolloutResponse;
                        await refreshBundleMetadata();
                        await refreshYaraForgeSyncStatus();
                        await refreshYaraRolloutStatus();
                        const bundleVersion = result.bundle_version ?? 'n/a';
                        const ruleCount = result.rule_count ?? 0;
                        const confirmation = result.confirmation;
                        const confirmationText = confirmation
                          ? ` Confirmed ${confirmation.confirmed_agents}/${confirmation.target_agents}, applied ${confirmation.applied}, partial ${confirmation.partial}, failed ${confirmation.failed}, pending ${confirmation.pending}.`
                          : '';
                        notifications.toasts.addSuccess(`YARA rollout triggered. Bundle version ${bundleVersion}, rules ${ruleCount}.`);
                        setBanner({
                          kind: confirmation?.timed_out ? 'error' : 'success',
                          message: result.message
                            ? `${result.message} Bundle version ${bundleVersion}, rules ${ruleCount}.${confirmationText}`
                            : `YARA rollout triggered. Bundle version ${bundleVersion}, rules ${ruleCount}.${confirmationText}`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to roll out YARA to all agents', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Failed to roll out YARA to all agents: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        setIsRollingOutYara(false);
                      }
                    }}
                  >
                    Rollout YARA to All Agents
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={isRetryingYaraRollout}
                    isDisabled={isRetryingYaraRollout}
                    onClick={async () => {
                      if (isRetryingYaraRollout) return;
                      setIsRetryingYaraRollout(true);
                      setBanner(null);
                      try {
                        const result = (await http.post('/api/xdr-defense/yara/rollouts/retry', {
                          body: JSON.stringify({}),
                        })) as YaraRolloutResponse;
                        await refreshYaraRolloutStatus();
                        const confirmation = result.confirmation;
                        const confirmationText = confirmation
                          ? ` Confirmed ${confirmation.confirmed_agents}/${confirmation.target_agents}, applied ${confirmation.applied}, partial ${confirmation.partial}, failed ${confirmation.failed}, pending ${confirmation.pending}.`
                          : '';
                        notifications.toasts.addSuccess('YARA rollout retry requested.');
                        setBanner({
                          kind: confirmation?.timed_out ? 'error' : 'success',
                          message: `${result.message ?? 'YARA rollout retry requested.'}${confirmationText}`,
                        });
                      } catch (err: unknown) {
                        notifications.toasts.addDanger({ title: 'Unable to retry YARA rollout', text: (err as Error)?.message });
                        setBanner({ kind: 'error', message: `Failed to retry YARA rollout: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        setIsRetryingYaraRollout(false);
                      }
                    }}
                  >
                    Retry YARA Rollout
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

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
                    await refreshBundleMetadata();
                    await refreshYaraRolloutStatus();
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
                `removed ${syncMeta?.removed ?? 0}`,
                `load failures ${syncMeta?.load_failures ?? 0}`,
                `rollout created ${syncMeta?.rollout?.created ?? 0}`,
                `rollout deduplicated ${syncMeta?.rollout?.deduplicated ?? 0}`,
                `signed rules ${bundleMetadata?.rule_count ?? yaraRules.length}`,
                `enabled rules ${bundleMetadata?.enabled_rule_count ?? activeCount}`,
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

        <EuiPanel>
          <EuiTitle size="s"><h3>YARA Rollout Status</h3></EuiTitle>
          <EuiSpacer size="s" />

          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" wrap>
            <EuiFlexItem grow={false}>
              <EuiText size="s" color="subdued">
                <p>
                  Agent rollout state is based on per-agent reports. Agents without recent reports are marked
                  offline/unknown (stale after {yaraRolloutStaleAfterMinutes} minutes).
                </p>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="xs"
                onClick={async () => {
                  await refreshYaraForgeSyncStatus();
                  await refreshBundleMetadata();
                  await refreshYaraRolloutStatus();
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
                itemId={(row: YaraRolloutStatusRow) => `${row.agent}-${row.policy}`}
                items={yaraRolloutRows}
                columns={yaraRolloutColumns as any}
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
                    value={String(yaraRolloutPageSize)}
                    onChange={(e) => {
                      setYaraRolloutPageSize(Number(e.target.value));
                      setYaraRolloutPageIndex(0);
                    }}
                    options={pageSizeOptions.map((o) => ({ value: String(o.value), text: o.text }))}
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiText size="s" color="subdued"><span>{yaraRolloutTotal} agent entries</span></EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiPagination
                pageCount={yaraRolloutTotalPages}
                activePage={rolloutCurrentPage}
                onPageClick={setYaraRolloutPageIndex}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        {drawerOpen === 'yara' && (
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="s" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Add Custom YARA Content</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiCallOut size="s" title="Stored in .xdr-defense-yara">
                <p>After saving custom content, click Rollout YARA to All Agents to publish the refreshed signed bundle.</p>
              </EuiCallOut>
              <EuiSpacer size="m" />
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
                        setBanner({ kind: 'success', message: 'Custom YARA content added. Click Rollout YARA to All Agents to publish the updated bundle.' });
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

  const renderProtectionTab = (input: {
    namespace: 'memory' | 'ransomware';
    title: string;
    description: string;
    syncButtonLabel: string;
    rolloutRows: ProtectionRolloutRow[];
    rolloutTotal: number;
    rolloutTotalPages: number;
    staleAfterMinutes: number;
    rolloutPageIndex: number;
    setRolloutPageIndex: React.Dispatch<React.SetStateAction<number>>;
    rolloutPageSize: number;
    setRolloutPageSize: React.Dispatch<React.SetStateAction<number>>;
    isSyncing: boolean;
    setIsSyncing: React.Dispatch<React.SetStateAction<boolean>>;
    syncSteps: ProtectionSyncStep[];
    setSyncSteps: React.Dispatch<React.SetStateAction<ProtectionSyncStep[]>>;
    syncStatusText: string;
    setSyncStatusText: React.Dispatch<React.SetStateAction<string>>;
    isRollingOut: boolean;
    setIsRollingOut: React.Dispatch<React.SetStateAction<boolean>>;
    isRetrying: boolean;
    setIsRetrying: React.Dispatch<React.SetStateAction<boolean>>;
    drawerId: 'memory' | 'ransomware';
    formName: string;
    setFormName: React.Dispatch<React.SetStateAction<string>>;
    formContent: string;
    setFormContent: React.Dispatch<React.SetStateAction<string>>;
    formSeverity: string;
    setFormSeverity: React.Dispatch<React.SetStateAction<string>>;
    formTags: string;
    setFormTags: React.Dispatch<React.SetStateAction<string>>;
    refreshRollout: (input?: { pageIndex?: number; pageSize?: number }) => Promise<void>;
  }) => {
    const currentPage = Math.min(input.rolloutPageIndex, Math.max(0, input.rolloutTotalPages - 1));
    const latestSyncStep = input.syncSteps.length > 0 ? input.syncSteps[input.syncSteps.length - 1] : null;

    return (
      <>
        <EuiPanel>
          <EuiFlexGroup justifyContent="spaceBetween" alignItems="flexStart" wrap>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s"><h3>{input.title} Registry</h3></EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued"><p>{input.description}</p></EuiText>
              <EuiSpacer size="s" />
              <EuiBadge color="hollow">index-backed registry content</EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" alignItems="center" wrap>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    isLoading={input.isSyncing}
                    isDisabled={input.isSyncing}
                    onClick={async () => {
                      input.setIsSyncing(true);
                      setBanner(null);
                      const localStart = new Date().toISOString();
                      input.setSyncStatusText('Queueing sync job...');
                      input.setSyncSteps([
                        {
                          stage: 'client_queue',
                          message: `Queueing ${input.title} sync job...`,
                          at: localStart
                        }
                      ]);
                      try {
                        const startResult = (await http.post(`/api/xdr-defense/${input.namespace}/open-source/sync/jobs`, {
                          body: JSON.stringify({}),
                        })) as ProtectionSyncJobStartResponse;

                        const pollIntervalMs = 900;
                        let jobState = startResult.job;
                        input.setSyncSteps(Array.isArray(jobState.steps) ? jobState.steps : []);
                        input.setSyncStatusText(startResult.already_running ? 'Sync already running; attaching to existing job.' : 'Sync started.');

                        while (jobState.status === 'running') {
                          await new Promise((resolve) => window.setTimeout(resolve, pollIntervalMs));
                          jobState = (await http.get(
                            `/api/xdr-defense/${input.namespace}/open-source/sync/jobs/${encodeURIComponent(jobState.job_id)}`
                          )) as ProtectionSyncJobStatus;
                          input.setSyncSteps(Array.isArray(jobState.steps) ? jobState.steps : []);
                          const latest = Array.isArray(jobState.steps) && jobState.steps.length > 0
                            ? jobState.steps[jobState.steps.length - 1]
                            : null;
                          if (latest?.message) {
                            input.setSyncStatusText(latest.message);
                          }
                        }

                        if (jobState.status === 'failed') {
                          throw new Error(jobState.error ?? `Failed to sync ${input.title.toLowerCase()} sources.`);
                        }

                        const result = jobState.result;
                        if (!result) {
                          throw new Error('Sync completed without a result payload.');
                        }

                        input.setSyncSteps(Array.isArray(jobState.steps) ? jobState.steps : result.steps ?? []);
                        input.setSyncStatusText('Sync completed.');

                        notifications.toasts.addSuccess(`${input.title} sync completed.`);
                        const candidateText = typeof result.upstream_candidate_rules === 'number'
                          ? ` Candidate pool ${result.upstream_candidate_rules}.`
                          : '';
                        const sourceBreakdownText = Array.isArray(result.source_breakdown) && result.source_breakdown.length > 0
                          ? ` Sources: ${result.source_breakdown
                              .map((source) => `${source.source} imported ${source.imported}, unchanged ${source.unchanged}, attempted ${source.attempted}`)
                              .join(' | ')}.`
                          : '';
                        setBanner({
                          kind: 'success',
                          message: `${input.title} sync completed. Source ${result.source_name}. Upstream total ${result.upstream_total_rules}.${candidateText} Curated ${result.curated_rules}. Attempted ${result.attempted}, imported ${result.imported}, unchanged ${result.unchanged}. Stored in ${result.index_name}.${sourceBreakdownText}`,
                        });
                      } catch (err: unknown) {
                        input.setSyncStatusText(`Sync failed: ${String((err as Error)?.message ?? err)}`);
                        setBanner({ kind: 'error', message: `Failed to sync ${input.title.toLowerCase()} feed: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        input.setIsSyncing(false);
                      }
                    }}
                  >
                    {input.syncButtonLabel}
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton onClick={() => setDrawerOpen(input.drawerId)}>Add Custom Content</EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={input.isRollingOut}
                    isDisabled={input.isRollingOut}
                    onClick={async () => {
                      input.setIsRollingOut(true);
                      setBanner(null);
                      try {
                        const result = (await http.post(`/api/xdr-defense/${input.namespace}/rollout`, {
                          body: JSON.stringify({ policy_id: 'global-default' }),
                        })) as { bundle_version?: number; rule_count?: number; message?: string };
                        await input.refreshRollout();
                        setBanner({
                          kind: 'success',
                          message: `${result.message ?? `${input.title} rollout triggered.`} Bundle version ${result.bundle_version ?? 'n/a'}, rules ${result.rule_count ?? 0}.`,
                        });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to roll out ${input.title.toLowerCase()} to all agents: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        input.setIsRollingOut(false);
                      }
                    }}
                  >
                    Rollout to All Agents
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    isLoading={input.isRetrying}
                    isDisabled={input.isRetrying}
                    onClick={async () => {
                      input.setIsRetrying(true);
                      setBanner(null);
                      try {
                        const result = (await http.post(`/api/xdr-defense/${input.namespace}/rollouts/retry`, {
                          body: JSON.stringify({}),
                        })) as { message?: string; bundle_version?: number; rule_count?: number };
                        await input.refreshRollout();
                        setBanner({
                          kind: 'success',
                          message: `${result.message ?? `${input.title} rollout retry requested.`} Bundle version ${result.bundle_version ?? 'n/a'}, rules ${result.rule_count ?? 0}.`,
                        });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to retry ${input.title.toLowerCase()} rollout: ${String((err as Error)?.message ?? err)}` });
                      } finally {
                        input.setIsRetrying(false);
                      }
                    }}
                  >
                    Retry Rollout
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        <EuiSpacer size="m" />

        <EuiPanel color="subdued" paddingSize="s">
          <EuiFlexGroup gutterSize="s" alignItems="center" justifyContent="spaceBetween" wrap>
            <EuiFlexItem grow={false}>
              <EuiBadge color={input.isSyncing ? 'warning' : 'hollow'}>
                sync {input.isSyncing ? 'in progress' : 'idle'}
              </EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={true}>
              <EuiText size="xs" color="subdued">
                <p>{latestSyncStep?.message ?? input.syncStatusText}</p>
              </EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
          {input.syncSteps.length > 0 && (
            <>
              <EuiSpacer size="xs" />
              <EuiText size="xs" color="subdued">
                <p>
                  {input.syncSteps
                    .slice(-6)
                    .map((step) => `${new Date(step.at).toLocaleTimeString()} - ${step.message}`)
                    .join(' | ')}
                </p>
              </EuiText>
            </>
          )}
        </EuiPanel>

        <EuiSpacer size="m" />

        <EuiPanel>
          <EuiTitle size="s"><h3>{input.title} Rollout Status</h3></EuiTitle>
          <EuiSpacer size="s" />
          <EuiText size="s" color="subdued">
            <p>Agents without recent reports are marked offline/unknown (stale after {input.staleAfterMinutes} minutes).</p>
          </EuiText>
          <EuiSpacer size="m" />
          <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '55vh' }}>
            <div style={{ display: 'inline-block', minWidth: 1200 }}>
              <EuiInMemoryTable
                itemId={(row: ProtectionRolloutRow) => `${row.agent}-${row.policy}`}
                items={input.rolloutRows}
                columns={protectionRolloutColumns as any}
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
                <EuiFlexItem grow={false}><EuiText size="s"><span>Rows per page</span></EuiText></EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiSelect
                    compressed
                    value={String(input.rolloutPageSize)}
                    onChange={(e) => {
                      input.setRolloutPageSize(Number(e.target.value));
                      input.setRolloutPageIndex(0);
                    }}
                    options={pageSizeOptions.map((o) => ({ value: String(o.value), text: o.text }))}
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}><EuiText size="s" color="subdued"><span>{input.rolloutTotal} agent entries</span></EuiText></EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiPagination
                pageCount={input.rolloutTotalPages}
                activePage={currentPage}
                onPageClick={input.setRolloutPageIndex}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        {drawerOpen === input.drawerId && (
          <EuiFlyout onClose={() => setDrawerOpen('none')} size="s" ownFocus>
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>Add Custom {input.title} Rule</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label="Name">
                    <EuiFieldText value={input.formName} onChange={(e) => input.setFormName(e.target.value)} placeholder="rule name" />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ width: 180 }}>
                  <EuiFormRow label="Severity">
                    <EuiSelect options={severityOptions} value={input.formSeverity} onChange={(e) => input.setFormSeverity(e.target.value)} />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="m" />
              <EuiFormRow label="Tags (comma-separated)">
                <EuiFieldText value={input.formTags} onChange={(e) => input.setFormTags(e.target.value)} placeholder="memory, custom" />
              </EuiFormRow>
              <EuiSpacer size="m" />
              <EuiFormRow label="Rule Content">
                <EuiTextArea
                  value={input.formContent}
                  onChange={(e) => input.setFormContent(e.target.value)}
                  placeholder="Structured detection or policy content"
                  style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', minHeight: 120 }}
                />
              </EuiFormRow>
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}><EuiButtonEmpty onClick={() => setDrawerOpen('none')}>Cancel</EuiButtonEmpty></EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    onClick={async () => {
                      setBanner(null);
                      try {
                        await http.post(`/api/xdr-defense/${input.namespace}/rules`, {
                          body: JSON.stringify({
                            name: input.formName,
                            content: input.formContent,
                            severity: input.formSeverity,
                            tags: input.formTags.split(',').map((t) => t.trim()).filter((t) => t.length > 0),
                          }),
                        });
                        input.setFormName('');
                        input.setFormContent('');
                        input.setFormSeverity('medium');
                        input.setFormTags('');
                        setDrawerOpen('none');
                        setBanner({ kind: 'success', message: `Custom ${input.title.toLowerCase()} rule added to the registry index.` });
                      } catch (err: unknown) {
                        setBanner({ kind: 'error', message: `Failed to add ${input.title.toLowerCase()} rule: ${String((err as Error)?.message ?? err)}` });
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

  const renderMemoryTab = () => renderProtectionTab({
    namespace: 'memory',
    title: 'Memory Protection',
    syncButtonLabel: 'Sync Capa feed',
    description: 'Manage memory-protection content sourced from curated capa mappings and custom index-backed entries.',
    rolloutRows: memoryRolloutRows,
    rolloutTotal: memoryRolloutTotal,
    rolloutTotalPages: memoryRolloutTotalPages,
    staleAfterMinutes: memoryRolloutStaleAfterMinutes,
    rolloutPageIndex: memoryRolloutPageIndex,
    setRolloutPageIndex: setMemoryRolloutPageIndex,
    rolloutPageSize: memoryRolloutPageSize,
    setRolloutPageSize: setMemoryRolloutPageSize,
    isSyncing: isSyncingMemorySource,
    setIsSyncing: setIsSyncingMemorySource,
    syncSteps: memorySyncSteps,
    setSyncSteps: setMemorySyncSteps,
    syncStatusText: memorySyncStatusText,
    setSyncStatusText: setMemorySyncStatusText,
    isRollingOut: isRollingOutMemory,
    setIsRollingOut: setIsRollingOutMemory,
    isRetrying: isRetryingMemoryRollout,
    setIsRetrying: setIsRetryingMemoryRollout,
    drawerId: 'memory',
    formName: memoryFormName,
    setFormName: setMemoryFormName,
    formContent: memoryFormContent,
    setFormContent: setMemoryFormContent,
    formSeverity: memoryFormSeverity,
    setFormSeverity: setMemoryFormSeverity,
    formTags: memoryFormTags,
    setFormTags: setMemoryFormTags,
    refreshRollout: refreshMemoryRolloutStatus,
  });

  const renderRansomwareTab = () => renderProtectionTab({
    namespace: 'ransomware',
    title: 'Ransomware',
    syncButtonLabel: 'Sync FalcoSecurity + Aqua Security',
    description: 'Manage ransomware protection content sourced from curated FalcoSecurity and Aqua Security (Tracee) mappings plus custom index-backed entries.',
    rolloutRows: ransomwareRolloutRows,
    rolloutTotal: ransomwareRolloutTotal,
    rolloutTotalPages: ransomwareRolloutTotalPages,
    staleAfterMinutes: ransomwareRolloutStaleAfterMinutes,
    rolloutPageIndex: ransomwareRolloutPageIndex,
    setRolloutPageIndex: setRansomwareRolloutPageIndex,
    rolloutPageSize: ransomwareRolloutPageSize,
    setRolloutPageSize: setRansomwareRolloutPageSize,
    isSyncing: isSyncingRansomwareSource,
    setIsSyncing: setIsSyncingRansomwareSource,
    syncSteps: ransomwareSyncSteps,
    setSyncSteps: setRansomwareSyncSteps,
    syncStatusText: ransomwareSyncStatusText,
    setSyncStatusText: setRansomwareSyncStatusText,
    isRollingOut: isRollingOutRansomware,
    setIsRollingOut: setIsRollingOutRansomware,
    isRetrying: isRetryingRansomwareRollout,
    setIsRetrying: setIsRetryingRansomwareRollout,
    drawerId: 'ransomware',
    formName: ransomwareFormName,
    setFormName: setRansomwareFormName,
    formContent: ransomwareFormContent,
    setFormContent: setRansomwareFormContent,
    formSeverity: ransomwareFormSeverity,
    setFormSeverity: setRansomwareFormSeverity,
    formTags: ransomwareFormTags,
    setFormTags: setRansomwareFormTags,
    refreshRollout: refreshRansomwareRolloutStatus,
  });

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
          { id: 'memory-protection', label: 'Memory Protection' },
          { id: 'ransomware-protection', label: 'Ransomware' },
          { id: 'behavioral-rules', label: 'Behavioral Rules' },
        ].map(({ id, label }) => (
          <EuiTab key={id} isSelected={activeTab === id} onClick={() => setActiveTab(id)}>
            {label}
          </EuiTab>
        ))}
      </EuiTabs>

      <EuiSpacer size="m" />

      {activeTab === 'detection-content' && renderYaraTab()}
      {activeTab === 'hashes' && renderHashesTab()}
      {activeTab === 'memory-protection' && renderMemoryTab()}
      {activeTab === 'ransomware-protection' && renderRansomwareTab()}
      {activeTab === 'behavioral-rules' && renderBehavioralTab()}
    </div>
  );
};
