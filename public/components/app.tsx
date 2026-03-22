import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  CriteriaWithPagination,
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCard,
  EuiCodeBlock,
  EuiCompressedFieldText,
  EuiCompressedFormRow,
  EuiCompressedSelect,
  EuiCompressedSwitch,
  EuiEmptyPrompt,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFlexGrid,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiHorizontalRule,
  EuiLink,
  EuiPageTemplate,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from '../../../../src/core/public';

type PolicyMode = 'detect' | 'prevent';
type ArtifactType = 'yara' | 'behavioral' | 'hashes' | 'threatintel';
type FeedType = 'hashes' | 'domain' | 'ip' | 'url';
type TabId = 'overview' | 'policy' | 'artifacts' | 'threatIntel' | 'response';
const POLICY_ROLLOUT_REFRESH_MS = 10_000;
const yaraRuleCatalogByArtifactID: Record<string, string[]> = {
  'yara-default': ['Baseline Malware Rule Bundle'],
  'yara-linux-elf-malware': [
    'Suspicious Packed ELF Binaries',
    'Suspicious ELF Shell Command Launchers',
    'Suspicious ELF Crypto Mining Indicators',
  ],
  'yara-cryptominers': ['XMRig Cryptominer Detection', 'Generic Cryptocurrency Miner Detection'],
  'yara-webshells': ['Generic PHP Web Shell Detection', 'Generic JSP Web Shell Detection'],
  'yara-rootkits': ['Kernel Module Rootkit Indicators', 'Process Hiding Rootkit Indicators'],
  'yara-play-esxi-ransomware': ['Detecting Play Ransomware on ESXi Hypervisors'],
  'yara-erlang-otp-ssh-vuln': ['Detecting Vulnerable Erlang/OTP SSH Binaries'],
  'yara-loaders-downloaders': [
    'Suspicious Curl/Wget Dropper Execution',
    'Suspicious ELF Downloader With Script Stager',
  ],
  'yara-credential-access-linux': [
    'Linux Password File Access Tooling',
    'SSH Private Key Collection Activity',
  ],
  'yara-wipers-disruptors': ['Destructive File Wiper Commands', 'Linux Service Disruption Tooling'],
};

interface DefensePolicy {
  mode: PolicyMode;
  capabilities: Record<string, boolean>;
  updatedAt: string;
  version: number;
}

interface ManagerPolicy {
  id: string;
  name: string;
  description?: string;
}

interface PolicyOverlayResponse extends DefensePolicy {
  manager_policy_id: string;
  rollout?: {
    policy_id: string;
    posture_version: number;
    target_agents: number;
    acked_agents: number;
    pending_agents: string[];
  };
}

interface PolicyOverlayListResponse {
  overlays: PolicyOverlayResponse[];
}

interface ManagerAgent {
  id: string;
  name: string;
  policyId: string;
  status: string;
  lastSeen: string;
  tags: string[];
  version: string;
}

interface ManagerAgentsResponse {
  agents: ManagerAgent[];
  policies: ManagerPolicy[];
}

interface SummaryResponse {
  policy: DefensePolicy;
  artifact_count: number;
  feed_count: number;
  prevention_enabled: boolean;
  rollback_enabled: boolean;
}

interface ArtifactEntry {
  id: string;
  type: ArtifactType;
  version: string;
  checksum: string;
  enabled: boolean;
  updatedAt: string;
  sourceUrl?: string;
  description?: string;
}

interface ArtifactListResponse {
  artifacts: ArtifactEntry[];
}

interface YaraForgeSyncStatusResponse {
  status?: 'idle' | 'downloading' | 'extracting' | 'processing' | 'completed' | 'failed';
  source?: string;
  sync_id?: string;
  started_at?: string;
  completed_at?: string;
  synced_at?: string;
  imported?: number;
  total_rules?: number;
  processed_rules?: number;
  version?: string;
  error?: string;
}

interface ThreatFeedEntry {
  id: string;
  name: string;
  type: FeedType;
  url: string;
  enabled: boolean;
  updatedAt: string;
  lastSyncAt?: string;
}

interface ThreatFeedListResponse {
  feeds: ThreatFeedEntry[];
}

interface ManifestResponse {
  manifest_version: number;
  policy_version: number;
  activation_timestamp: string;
  artifacts: Array<Record<string, unknown>>;
}

interface CorrelationRuleResponse {
  rules: Array<{
    id: string;
    name: string;
    source: Record<string, unknown>;
  }>;
}

interface RollbackResponse {
  status: string;
  agent_id: string;
  incident_id: string;
  reason?: string;
  confirmed_at: string;
}

interface PolicyRolloutResponse {
  policy_id: string;
  posture_version: number;
  updated_at: string;
  target_agent_ids: string[];
  acked_agent_ids: string[];
  pending_agent_ids: string[];
  acked_agents: Array<{
    agent_id: string;
    hostname?: string;
    acked_at: string;
  }>;
  retry_requested_at: Record<string, string>;
}

interface RolloutTableRow {
  id: string;
  agentID: string;
  agentName: string;
  status: 'acked' | 'pending';
  lastRetryRequested: string;
}

type YaraRolloutAction = 'sync' | 'activate' | 'deactivate' | 'delete';
type YaraRolloutAgentState = 'pending' | 'acked' | 'failed';

interface YaraRolloutAgentStatus {
  agent_id: string;
  hostname?: string;
  state: YaraRolloutAgentState;
  last_action: YaraRolloutAction;
  last_attempted_at: string;
  acked_at?: string;
  failure_reason?: string;
  retry_requested_at?: string;
}

interface YaraRolloutSummaryResponse {
  manager_policy_id: string;
  rollout_version: number;
  action: YaraRolloutAction;
  artifact_ids: string[];
  updated_at: string;
  target_agent_ids: string[];
  pending_agent_ids: string[];
  acked_agent_ids: string[];
  failed_agent_ids: string[];
  stale_pending_agent_ids: string[];
  stale_after_seconds: number;
  agents: YaraRolloutAgentStatus[];
}

interface YaraRolloutFailureRow {
  id: string;
  agentID: string;
  agentName: string;
  action: YaraRolloutAction;
  failureType: 'ack_failed' | 'stale_pending';
  details: string;
  lastAttemptedAt: string;
}

interface XdrDefenseAppDeps {
  basename: string;
  notifications: CoreStart['notifications'];
  http: CoreStart['http'];
}

const capabilityGroups = [
  {
    title: 'Malware detection',
    description: 'Single-event malware scanning on the agent before correlation reaches OpenSearch.',
    keys: [
      'malware.hash_detection',
      'malware.yara_detection',
      'malware.static_detection',
      'malware.execution_blocking',
    ],
  },
  {
    title: 'Behavior and memory',
    description: 'Behavioral, fileless, injection, and hollowing visibility for on-host detections.',
    keys: [
      'ransomware.behavior_detection',
      'ransomware.shield',
      'memory.injection',
      'memory.hollowing',
      'memory.fileless',
    ],
  },
  {
    title: 'Response orchestration',
    description: 'Policy gates for prevention, rollback, and OpenSearch-side correlation.',
    keys: ['prevention.enabled', 'rollback.enabled', 'correlation.enabled'],
  },
];

const artifactTypeOptions = [
  { value: 'yara', text: 'YARA rules' },
  { value: 'behavioral', text: 'Behavioral rules' },
  { value: 'hashes', text: 'Hash reputation set' },
  { value: 'threatintel', text: 'Threat intel package' },
];

const feedTypeOptions = [
  { value: 'hashes', text: 'Hashes' },
  { value: 'domain', text: 'Domains' },
  { value: 'ip', text: 'IP addresses' },
  { value: 'url', text: 'URLs' },
];

const defaultCapabilities: Record<string, boolean> = {
  'malware.hash_detection': true,
  'malware.yara_detection': true,
  'malware.static_detection': true,
  'malware.execution_blocking': false,
  'ransomware.behavior_detection': true,
  'ransomware.shield': false,
  'memory.injection': true,
  'memory.hollowing': true,
  'memory.fileless': true,
  'prevention.enabled': false,
  'rollback.enabled': true,
  'correlation.enabled': true,
};

const createDefaultPolicyState = (): DefensePolicy => ({
  mode: 'detect',
  capabilities: { ...defaultCapabilities },
  updatedAt: new Date().toISOString(),
  version: 1,
});

const prettyDate = (value?: string) => {
  if (!value) {
    return 'never';
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return value;
  }
  return new Date(parsed).toLocaleString();
};

const isSettledFulfilled = <T,>(result: PromiseSettledResult<T>): result is PromiseFulfilledResult<T> =>
  result.status === 'fulfilled';

export const XdrDefenseApp = ({ http, notifications }: XdrDefenseAppDeps) => {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [artifacts, setArtifacts] = useState<ArtifactEntry[]>([]);
  const [feeds, setFeeds] = useState<ThreatFeedEntry[]>([]);
  const [manifest, setManifest] = useState<ManifestResponse | null>(null);
  const [correlationRules, setCorrelationRules] = useState<CorrelationRuleResponse['rules']>([]);
  const [lastActionResult, setLastActionResult] = useState<Record<string, unknown> | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSavingPolicy, setIsSavingPolicy] = useState(false);
  const [isSavingArtifact, setIsSavingArtifact] = useState(false);
  const [isSavingFeed, setIsSavingFeed] = useState(false);
  const [isSyncingYaraForge, setIsSyncingYaraForge] = useState(false);
  const [isConfirmingRollback, setIsConfirmingRollback] = useState(false);
  const [selectedArtifactID, setSelectedArtifactID] = useState<string | null>(null);
  const [selectedArtifactIDs, setSelectedArtifactIDs] = useState<string[]>([]);
  const [artifactPageIndex, setArtifactPageIndex] = useState(0);
  const [artifactPageSize, setArtifactPageSize] = useState(20);
  const [bulkArtifactOperation, setBulkArtifactOperation] = useState<'activate' | 'deactivate' | 'delete' | null>(null);
  const [yaraForgeSyncStatus, setYaraForgeSyncStatus] = useState<YaraForgeSyncStatusResponse | null>(null);
  const [isCustomContentDrawerOpen, setIsCustomContentDrawerOpen] = useState(false);
  const [latestYaraRollout, setLatestYaraRollout] = useState<YaraRolloutSummaryResponse | null>(null);
  const [isRetryingYaraRollout, setIsRetryingYaraRollout] = useState(false);

  const [mode, setMode] = useState<PolicyMode>('detect');
  const [capabilities, setCapabilities] = useState<Record<string, boolean>>({ ...defaultCapabilities });
  const [managerPolicies, setManagerPolicies] = useState<ManagerPolicy[]>([]);
  const [policyOverlays, setPolicyOverlays] = useState<Record<string, DefensePolicy>>({});
  const [selectedManagerPolicyID, setSelectedManagerPolicyID] = useState<string>('default');
  const [managerAgents, setManagerAgents] = useState<ManagerAgent[]>([]);
  const [latestRollout, setLatestRollout] = useState<PolicyRolloutResponse | null>(null);
  const [selectedRetryAgentIDs, setSelectedRetryAgentIDs] = useState<string[]>([]);
  const [isRetryingRollout, setIsRetryingRollout] = useState(false);

  const [artifactId, setArtifactId] = useState('');
  const [artifactType, setArtifactType] = useState<ArtifactType>('yara');
  const [artifactVersion, setArtifactVersion] = useState('');
  const [artifactChecksum, setArtifactChecksum] = useState('');
  const [artifactSourceUrl, setArtifactSourceUrl] = useState('');
  const [artifactDescription, setArtifactDescription] = useState('');

  const [feedId, setFeedId] = useState('');
  const [feedName, setFeedName] = useState('');
  const [feedType, setFeedType] = useState<FeedType>('hashes');
  const [feedUrl, setFeedUrl] = useState('');

  const [rollbackAgentId, setRollbackAgentId] = useState('');
  const [rollbackIncidentId, setRollbackIncidentId] = useState('');
  const [rollbackReason, setRollbackReason] = useState('');
  const skipNextPolicyScopedLoadRef = useRef(false);
  const lastSeenForgeProcessedRef = useRef(0);
  const lastSeenForgeSyncIDRef = useRef<string | null>(null);
  const lastHandledForgeTerminalStatusRef = useRef<string | null>(null);
  const pendingYaraSyncTargetsRef = useRef<string[]>([]);

  const api = async <T,>(
    path: string,
    init?: {
      method?: string;
      body?: string;
      query?: Record<string, string | number | boolean | undefined>;
    }
  ): Promise<T> => {
    if (!init?.method || init.method === 'GET') {
      return http.get<T>(path, {
        query: init?.query,
      });
    }
    return http.fetch<T>(path, {
      method: init.method,
      body: init.body,
      query: init.query,
      headers: {
        'content-type': 'application/json',
      },
    });
  };

  const toastError = (title: string, error: unknown) => {
    notifications.toasts.addDanger({
      title,
      text: error instanceof Error ? error.message : String(error),
    });
  };

  const toastWarning = (title: string, error: unknown) => {
    notifications.toasts.addWarning({
      title,
      text: error instanceof Error ? error.message : String(error),
    });
  };

  const selectPolicyID = (policies: ManagerPolicy[], currentID?: string) => {
    if (currentID && policies.some((policy) => policy.id === currentID)) {
      return currentID;
    }
    if (policies.length > 0) {
      return policies[0].id;
    }
    return 'default';
  };

  const applyFallbackPolicyState = (policyID: string) => {
    const fallback = createDefaultPolicyState();
    setMode(fallback.mode);
    setCapabilities(fallback.capabilities);
    setPolicyOverlays((current) => ({
      ...current,
      [policyID]: fallback,
    }));
    setSummary((current) =>
      current
        ? {
            ...current,
            policy: fallback,
            prevention_enabled: Boolean(fallback.capabilities['prevention.enabled']),
            rollback_enabled: Boolean(fallback.capabilities['rollback.enabled']),
          }
        : {
            policy: fallback,
            artifact_count: artifacts.length,
            feed_count: feeds.length,
            prevention_enabled: Boolean(fallback.capabilities['prevention.enabled']),
            rollback_enabled: Boolean(fallback.capabilities['rollback.enabled']),
          }
    );
    setLatestRollout(null);
    setSelectedRetryAgentIDs([]);
  };

  const loadSharedData = async () => {
    const [feedResult, correlationResult, managerResult, overlaysResult] =
      await Promise.allSettled([
        api<ThreatFeedListResponse>('/api/xdr-defense/threat-intel/feeds'),
        api<CorrelationRuleResponse>('/api/xdr-defense/correlation-rules'),
        api<ManagerAgentsResponse>('/api/xdr_manager/agents'),
        api<PolicyOverlayListResponse>('/api/xdr-defense/policy-overlays'),
      ]);

    if (isSettledFulfilled(feedResult)) {
      setFeeds(feedResult.value.feeds ?? []);
    } else {
      setFeeds([]);
      toastWarning('Unable to load threat intel feeds', feedResult.reason);
    }

    if (isSettledFulfilled(correlationResult)) {
      setCorrelationRules(correlationResult.value.rules ?? []);
    } else {
      setCorrelationRules([]);
      toastWarning('Unable to load correlation rules', correlationResult.reason);
    }

    const policies = isSettledFulfilled(managerResult) ? managerResult.value.policies ?? [] : [];
    const agents = isSettledFulfilled(managerResult) ? managerResult.value.agents ?? [] : [];
    if (!isSettledFulfilled(managerResult)) {
      toastWarning('Unable to load manager policies, using default policy', managerResult.reason);
    }
    setManagerPolicies(policies);
    setManagerAgents(agents);

    if (isSettledFulfilled(overlaysResult)) {
      const overlayByPolicyID = overlaysResult.value.overlays.reduce<Record<string, DefensePolicy>>((acc, overlay) => {
        acc[overlay.manager_policy_id] = {
          mode: overlay.mode,
          capabilities: overlay.capabilities,
          updatedAt: overlay.updatedAt,
          version: overlay.version,
        };
        return acc;
      }, {});
      setPolicyOverlays(overlayByPolicyID);
    } else {
      setPolicyOverlays({});
      toastWarning('Unable to load policy overlays', overlaysResult.reason);
    }

    return {
      policies,
      selectedPolicyID: isSettledFulfilled(managerResult)
        ? selectPolicyID(policies, selectedManagerPolicyID)
        : 'default',
    };
  };

  const loadPolicySummaryAndManifest = async (policyID: string) => {
    const [summaryResult, manifestResult] = await Promise.allSettled([
      api<SummaryResponse>('/api/xdr-defense/summary', {
        query: { policy_id: policyID },
      }),
      api<ManifestResponse>('/api/xdr-defense/artifacts/manifest/latest', {
        query: { policy_id: policyID },
      }),
    ]);

    if (isSettledFulfilled(summaryResult)) {
      setSummary(summaryResult.value);
    } else {
      toastWarning('Unable to load selected policy summary', summaryResult.reason);
    }

    if (isSettledFulfilled(manifestResult)) {
      setManifest(manifestResult.value);
    } else {
      setManifest(null);
      toastWarning('Unable to load selected policy manifest', manifestResult.reason);
    }
  };

  const refreshArtifactsAndManifest = async (policyID: string) => {
    const [artifactResult] = await Promise.allSettled([
      api<ArtifactListResponse>('/api/xdr-defense/artifacts', {
        query: { policy_id: policyID },
      }),
      loadPolicySummaryAndManifest(policyID),
    ]);

    if (isSettledFulfilled(artifactResult)) {
      const nextArtifacts = artifactResult.value.artifacts ?? [];
      setArtifacts(nextArtifacts);
      return nextArtifacts;
    }

    setArtifacts([]);
    toastWarning('Unable to refresh artifacts after sync', artifactResult.reason);
    return [];
  };

  const loadLatestRollout = async (
    policyID: string,
    showErrorToast = true,
    resetSelection = true
  ) => {
    const encodedPolicyID = encodeURIComponent(policyID);
    try {
      const rollout = await api<PolicyRolloutResponse>(
        `/api/xdr-defense/policy-rollouts/${encodedPolicyID}/latest`
      );
      setLatestRollout(rollout);
      if (resetSelection) {
        setSelectedRetryAgentIDs([]);
      } else {
        const pendingSet = new Set(rollout.pending_agent_ids);
        setSelectedRetryAgentIDs((current) => current.filter((agentID) => pendingSet.has(agentID)));
      }
    } catch (error) {
      setLatestRollout(null);
      setSelectedRetryAgentIDs([]);
      if (showErrorToast) {
        toastWarning('Unable to load latest rollout status', error);
      }
    }
  };

  const resolvePolicyTargetAgentIDs = async (_policyID: string) => {
    try {
      const managerSnapshot = await api<ManagerAgentsResponse>('/api/xdr_manager/agents');
      setManagerPolicies(managerSnapshot.policies ?? []);
      setManagerAgents(managerSnapshot.agents ?? []);
      return (managerSnapshot.agents ?? []).map((agent) => agent.id);
    } catch (error) {
      toastWarning('Unable to refresh manager agent targets', error);
      return managerAgents.map((agent) => agent.id);
    }
  };

  const loadLatestYaraRollout = async (policyID: string, showErrorToast = false) => {
    const encodedPolicyID = encodeURIComponent(policyID);
    try {
      const rollout = await api<YaraRolloutSummaryResponse>(
        `/api/xdr-defense/yara-rollouts/${encodedPolicyID}/latest`,
        {
          query: { stale_after_seconds: 900 },
        }
      );
      setLatestYaraRollout(rollout);
      return rollout;
    } catch (error) {
      setLatestYaraRollout(null);
      if (showErrorToast) {
        toastWarning('Unable to load YARA rollout status', error);
      }
      return null;
    }
  };

  const reconcileYaraRollout = async (
    action: YaraRolloutAction,
    policyID: string,
    targetAgentIDs?: string[]
  ) => {
    try {
      const effectiveTargets = targetAgentIDs ?? (await resolvePolicyTargetAgentIDs(policyID));
      const encodedPolicyID = encodeURIComponent(policyID);
      const rollout = await api<YaraRolloutSummaryResponse>(
        `/api/xdr-defense/yara-rollouts/${encodedPolicyID}/reconcile`,
        {
          method: 'POST',
          body: JSON.stringify({
            action,
            target_agent_ids: effectiveTargets,
          }),
        }
      );
      setLatestYaraRollout(rollout);
      return rollout;
    } catch (error) {
      toastWarning('Unable to create YARA rollout tracking', error);
      return null;
    }
  };

  const loadPolicyScopedData = async (policyID: string, showOverlayErrorToast = true) => {
    const encodedPolicyID = encodeURIComponent(policyID);
    const overlayResult = await Promise.allSettled([
      api<PolicyOverlayResponse>(`/api/xdr-defense/policy-overlays/${encodedPolicyID}`),
      api<ArtifactListResponse>('/api/xdr-defense/artifacts', {
        query: { policy_id: policyID },
      }),
      loadPolicySummaryAndManifest(policyID),
      loadLatestRollout(policyID, showOverlayErrorToast),
      loadLatestYaraRollout(policyID),
    ]);

    const overlayFetchResult = overlayResult[0];
    const artifactFetchResult = overlayResult[1];

    if (isSettledFulfilled(artifactFetchResult)) {
      setArtifacts(artifactFetchResult.value.artifacts ?? []);
    } else {
      setArtifacts([]);
      toastWarning('Unable to load policy-scoped artifacts', artifactFetchResult.reason);
    }

    if (isSettledFulfilled(overlayFetchResult)) {
      const overlayResponse = overlayFetchResult.value;
      setMode(overlayResponse.mode);
      setCapabilities(overlayResponse.capabilities);
      setPolicyOverlays((current) => ({
        ...current,
        [policyID]: {
          mode: overlayResponse.mode,
          capabilities: overlayResponse.capabilities,
          updatedAt: overlayResponse.updatedAt,
          version: overlayResponse.version,
        },
      }));
      return;
    }

    if (showOverlayErrorToast) {
      toastError('Unable to load selected defense posture', overlayFetchResult.reason);
    }
    applyFallbackPolicyState(policyID);
  };

  const loadData = async () => {
    setIsLoading(true);
    try {
      const shared = await loadSharedData();
      const nextPolicyID = shared.selectedPolicyID;
      skipNextPolicyScopedLoadRef.current = true;
      setSelectedManagerPolicyID(nextPolicyID);
      await loadPolicyScopedData(nextPolicyID, false);
    } catch (error) {
      toastError('Unable to load XDR Defense data', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (!selectedManagerPolicyID) {
      return;
    }

    if (skipNextPolicyScopedLoadRef.current) {
      skipNextPolicyScopedLoadRef.current = false;
      return;
    }

    loadPolicyScopedData(selectedManagerPolicyID);
  }, [selectedManagerPolicyID]);

  useEffect(() => {
    if (artifacts.length === 0) {
      setSelectedArtifactID(null);
      return;
    }

    if (selectedArtifactID && artifacts.some((artifact) => artifact.id === selectedArtifactID)) {
      return;
    }

    setSelectedArtifactID(artifacts[0].id);
  }, [artifacts, selectedArtifactID]);

  useEffect(() => {
    const artifactIDSet = new Set(artifacts.map((artifact) => artifact.id));
    setSelectedArtifactIDs((current) => current.filter((artifactID) => artifactIDSet.has(artifactID)));

    const lastPageIndex = Math.max(0, Math.ceil(artifacts.length / artifactPageSize) - 1);
    setArtifactPageIndex((current) => (current > lastPageIndex ? lastPageIndex : current));
  }, [artifacts, artifactPageSize]);

  useEffect(() => {
    if (activeTab !== 'policy' || !selectedManagerPolicyID) {
      return;
    }

    const refreshTracking = async () => {
      const encodedPolicyID = encodeURIComponent(selectedManagerPolicyID);
      const [rolloutResult, managerResult] = await Promise.allSettled([
        api<PolicyRolloutResponse>(`/api/xdr-defense/policy-rollouts/${encodedPolicyID}/latest`),
        api<ManagerAgentsResponse>('/api/xdr_manager/agents'),
      ]);

      if (isSettledFulfilled(rolloutResult)) {
        const rollout = rolloutResult.value;
        setLatestRollout(rollout);
        const pendingSet = new Set(rollout.pending_agent_ids);
        setSelectedRetryAgentIDs((current) => current.filter((agentID) => pendingSet.has(agentID)));
      }

      if (isSettledFulfilled(managerResult)) {
        setManagerAgents(managerResult.value.agents ?? []);
      }
    };

    // Prime the panel immediately, then keep it fresh like the manager agents table.
    void refreshTracking();
    const intervalID = window.setInterval(() => {
      void refreshTracking();
    }, POLICY_ROLLOUT_REFRESH_MS);

    return () => {
      window.clearInterval(intervalID);
    };
  }, [activeTab, selectedManagerPolicyID]);

  const toggleCapability = (key: string, value: boolean) => {
    setCapabilities((current) => ({ ...current, [key]: value }));
  };

  const savePolicy = async () => {
    setIsSavingPolicy(true);
    try {
      const managerSnapshot = await api<ManagerAgentsResponse>('/api/xdr_manager/agents');
      const targetAgentIDs = (managerSnapshot.agents ?? [])
        .filter((agent) => agent.policyId === selectedManagerPolicyID)
        .map((agent) => agent.id);

      const encodedPolicyID = encodeURIComponent(selectedManagerPolicyID);
      const response = await api<PolicyOverlayResponse>(`/api/xdr-defense/policy-overlays/${encodedPolicyID}`, {
        method: 'PUT',
        body: JSON.stringify({ mode, capabilities, target_agent_ids: targetAgentIDs }),
      });
      setLastActionResult(response as unknown as Record<string, unknown>);
      setMode(response.mode);
      setCapabilities(response.capabilities);
      setManagerPolicies(managerSnapshot.policies ?? []);
      setManagerAgents(managerSnapshot.agents ?? []);
      setPolicyOverlays((current) => ({
        ...current,
        [selectedManagerPolicyID]: {
          mode: response.mode,
          capabilities: response.capabilities,
          updatedAt: response.updatedAt,
          version: response.version,
        },
      }));
      notifications.toasts.addSuccess(`Defense posture updated for ${selectedManagerPolicyID}`);
      await loadPolicySummaryAndManifest(selectedManagerPolicyID);
      await loadLatestRollout(selectedManagerPolicyID, false);
    } catch (error) {
      toastError('Unable to save policy', error);
    } finally {
      setIsSavingPolicy(false);
    }
  };

  const saveArtifact = async () => {
    setIsSavingArtifact(true);
    try {
      const response = await api<ArtifactEntry>('/api/xdr-defense/artifacts', {
        method: 'POST',
        body: JSON.stringify({
          id: artifactId,
          type: artifactType,
          version: artifactVersion,
          checksum: artifactChecksum,
          enabled: true,
          sourceUrl: artifactSourceUrl || undefined,
          description: artifactDescription || undefined,
        }),
      });
      setLastActionResult(response as unknown as Record<string, unknown>);
      notifications.toasts.addSuccess('Artifact registered');
      setArtifactId('');
      setArtifactVersion('');
      setArtifactChecksum('');
      setArtifactSourceUrl('');
      setArtifactDescription('');
      setIsCustomContentDrawerOpen(false);
      await loadData();
    } catch (error) {
      toastError('Unable to save artifact', error);
    } finally {
      setIsSavingArtifact(false);
    }
  };

  const updateSelectedArtifactsState = async (enabled: boolean) => {
    const selectedIDs = selectedArtifactIDs.filter((artifactID) =>
      artifacts.some((artifact) => artifact.id === artifactID)
    );
    if (selectedIDs.length === 0) {
      return;
    }

    const previousArtifacts = artifacts;
    const operation = enabled ? 'activate' : 'deactivate';

    setBulkArtifactOperation(operation);
    setArtifacts((current) =>
      current.map((artifact) =>
        selectedIDs.includes(artifact.id) ? { ...artifact, enabled } : artifact
      )
    );

    const results = await Promise.allSettled(
      selectedIDs.map(async (artifactID) => {
        const encodedID = encodeURIComponent(artifactID);
        const response = await api<ArtifactEntry>(`/api/xdr-defense/artifacts/${encodedID}/state`, {
          method: 'PUT',
          query: { policy_id: selectedManagerPolicyID },
          body: JSON.stringify({ enabled }),
        });
        return { artifactID, response };
      })
    );

    const failedEntries: Array<{ artifactID: string; reason: unknown }> = [];
    const successfulResponses: ArtifactEntry[] = [];

    results.forEach((result, index) => {
      const artifactID = selectedIDs[index];
      if (result.status === 'fulfilled') {
        successfulResponses.push(result.value.response);
      } else {
        failedEntries.push({ artifactID, reason: result.reason });
      }
    });

    if (failedEntries.length > 0) {
      const failedIDSet = new Set(failedEntries.map((entry) => entry.artifactID));
      setArtifacts((current) =>
        current.map((artifact) => {
          if (!failedIDSet.has(artifact.id)) {
            return artifact;
          }

          const previousArtifact = previousArtifacts.find((candidate) => candidate.id === artifact.id);
          return previousArtifact ?? artifact;
        })
      );
      toastError(
        `Unable to ${enabled ? 'activate' : 'deactivate'} ${failedEntries.length} artifact${failedEntries.length === 1 ? '' : 's'}`,
        failedEntries[0].reason
      );
    }

    if (successfulResponses.length > 0) {
      setLastActionResult(successfulResponses[successfulResponses.length - 1] as unknown as Record<string, unknown>);
      notifications.toasts.addSuccess(
        `${enabled ? 'Activated' : 'Deactivated'} ${successfulResponses.length} artifact${successfulResponses.length === 1 ? '' : 's'}`
      );
      void loadPolicySummaryAndManifest(selectedManagerPolicyID);
      void reconcileYaraRollout(enabled ? 'activate' : 'deactivate', selectedManagerPolicyID);
    }

    setBulkArtifactOperation(null);
  };

  const deleteSelectedArtifacts = async () => {
    const selectedIDs = selectedArtifactIDs.filter((artifactID) =>
      artifacts.some((artifact) => artifact.id === artifactID)
    );
    if (selectedIDs.length === 0) {
      return;
    }

    const confirmed = window.confirm(
      `Delete ${selectedIDs.length} selected artifact${selectedIDs.length === 1 ? '' : 's'}? This cannot be undone.`
    );
    if (!confirmed) {
      return;
    }

    const previousArtifacts = artifacts;
    const selectedSet = new Set(selectedIDs);
    const previousSelectedArtifactID = selectedArtifactID;

    setBulkArtifactOperation('delete');
    setArtifacts((current) => current.filter((artifact) => !selectedSet.has(artifact.id)));
    setSelectedArtifactIDs([]);
    if (previousSelectedArtifactID && selectedSet.has(previousSelectedArtifactID)) {
      setSelectedArtifactID(null);
    }

    const results = await Promise.allSettled(
      selectedIDs.map(async (artifactID) => {
        const encodedID = encodeURIComponent(artifactID);
        const response = await api<Record<string, unknown>>(`/api/xdr-defense/artifacts/${encodedID}`, {
          method: 'DELETE',
        });
        return { artifactID, response };
      })
    );

    const successfulIDs = new Set<string>();
    const failedEntries: Array<{ artifactID: string; reason: unknown }> = [];
    const successfulResponses: Record<string, unknown>[] = [];

    results.forEach((result, index) => {
      const artifactID = selectedIDs[index];
      if (result.status === 'fulfilled') {
        successfulIDs.add(artifactID);
        successfulResponses.push(result.value.response);
      } else {
        failedEntries.push({ artifactID, reason: result.reason });
      }
    });

    if (failedEntries.length > 0) {
      const successfulSet = new Set(successfulIDs);
      setArtifacts(previousArtifacts.filter((artifact) => !successfulSet.has(artifact.id)));
      setSelectedArtifactIDs(failedEntries.map((entry) => entry.artifactID));
      setSelectedArtifactID((current) => {
        if (current && failedEntries.some((entry) => entry.artifactID === current)) {
          return current;
        }
        return previousSelectedArtifactID;
      });
      toastError(
        `Unable to delete ${failedEntries.length} artifact${failedEntries.length === 1 ? '' : 's'}`,
        failedEntries[0].reason
      );
    }

    if (successfulIDs.size > 0) {
      setLastActionResult(successfulResponses[successfulResponses.length - 1]);
      notifications.toasts.addSuccess(
        `Deleted ${successfulIDs.size} artifact${successfulIDs.size === 1 ? '' : 's'}`
      );
      void loadPolicySummaryAndManifest(selectedManagerPolicyID);
      void reconcileYaraRollout('delete', selectedManagerPolicyID);
    }

    setBulkArtifactOperation(null);
  };

  const syncYaraForgeCore = async () => {
    try {
      const policyID = selectedManagerPolicyID || 'default';
      pendingYaraSyncTargetsRef.current = await resolvePolicyTargetAgentIDs(policyID);
      const response = await api<{
        status: string;
        started: boolean;
        syncID?: string;
        metadata?: YaraForgeSyncStatusResponse;
      }>(
        '/api/xdr-defense/yara-forge/sync',
        {
          method: 'POST',
          body: JSON.stringify({}),
        }
      );
      setIsSyncingYaraForge(true);
      setYaraForgeSyncStatus(response.metadata ?? { status: response.status === 'running' ? 'processing' : 'downloading' });
      lastSeenForgeProcessedRef.current = 0;
      lastSeenForgeSyncIDRef.current = response.syncID ?? response.metadata?.sync_id ?? null;
      lastHandledForgeTerminalStatusRef.current = null;
      setLastActionResult(response as unknown as Record<string, unknown>);
      notifications.toasts.addSuccess(
        response.started ? 'YARA Forge Core sync started' : 'YARA Forge Core sync is already running'
      );
      void refreshArtifactsAndManifest(policyID);
    } catch (error) {
      toastError('Unable to sync YARA Forge Core', error);
    }
  };

  useEffect(() => {
    if (activeTab !== 'artifacts') {
      return;
    }

    let isCancelled = false;

    const pollSyncStatus = async () => {
      try {
        const status = await api<YaraForgeSyncStatusResponse>('/api/xdr-defense/yara-forge/status');
        if (isCancelled) {
          return;
        }

        setYaraForgeSyncStatus(status);
        const statusValue = status.status ?? 'idle';
        const isActive = ['downloading', 'extracting', 'processing'].includes(statusValue);
        setIsSyncingYaraForge(isActive);

        if (status.sync_id && status.sync_id !== lastSeenForgeSyncIDRef.current) {
          lastSeenForgeSyncIDRef.current = status.sync_id;
          lastSeenForgeProcessedRef.current = 0;
          lastHandledForgeTerminalStatusRef.current = null;
        }

        const processedRules = status.processed_rules ?? 0;
        if (processedRules > lastSeenForgeProcessedRef.current) {
          lastSeenForgeProcessedRef.current = processedRules;
          await refreshArtifactsAndManifest(selectedManagerPolicyID || 'default');
        }

        const terminalStatusKey = `${status.sync_id ?? 'none'}:${statusValue}`;

        if (statusValue === 'completed' && lastHandledForgeTerminalStatusRef.current !== terminalStatusKey) {
          lastHandledForgeTerminalStatusRef.current = terminalStatusKey;
          await refreshArtifactsAndManifest(selectedManagerPolicyID || 'default');
          await reconcileYaraRollout(
            'sync',
            selectedManagerPolicyID || 'default',
            pendingYaraSyncTargetsRef.current
          );
          await loadLatestRollout(selectedManagerPolicyID || 'default', false, false);
          await loadLatestYaraRollout(selectedManagerPolicyID || 'default');
          setLastActionResult(status as unknown as Record<string, unknown>);
          setIsSyncingYaraForge(false);
        }

        if (statusValue === 'failed' && lastHandledForgeTerminalStatusRef.current !== terminalStatusKey) {
          lastHandledForgeTerminalStatusRef.current = terminalStatusKey;
          setLastActionResult(status as unknown as Record<string, unknown>);
          setIsSyncingYaraForge(false);
        }

        await loadLatestYaraRollout(selectedManagerPolicyID || 'default');
      } catch (error) {
        if (!isCancelled) {
          toastWarning('Unable to load YARA Forge sync status', error);
        }
      }
    };

    void pollSyncStatus();
    const intervalID = window.setInterval(() => {
      void pollSyncStatus();
    }, 1000);

    return () => {
      isCancelled = true;
      window.clearInterval(intervalID);
    };
  }, [activeTab, selectedManagerPolicyID]);

  const saveFeed = async () => {
    setIsSavingFeed(true);
    try {
      const response = await api<ThreatFeedEntry>('/api/xdr-defense/threat-intel/feeds', {
        method: 'POST',
        body: JSON.stringify({
          id: feedId,
          name: feedName,
          type: feedType,
          url: feedUrl,
          enabled: true,
        }),
      });
      setLastActionResult(response as unknown as Record<string, unknown>);
      notifications.toasts.addSuccess('Threat intel feed saved');
      setFeedId('');
      setFeedName('');
      setFeedUrl('');
      await loadData();
    } catch (error) {
      toastError('Unable to save feed', error);
    } finally {
      setIsSavingFeed(false);
    }
  };

  const syncFeed = async (feedID: string) => {
    try {
      const response = await api<Record<string, unknown>>('/api/xdr-defense/threat-intel/sync', {
        method: 'POST',
        body: JSON.stringify({ feed_id: feedID }),
      });
      setLastActionResult(response);
      notifications.toasts.addSuccess(`Threat intel sync queued for ${feedID}`);
      await loadData();
    } catch (error) {
      toastError('Unable to sync threat intel feed', error);
    }
  };

  const confirmRollback = async () => {
    setIsConfirmingRollback(true);
    try {
      const response = await api<RollbackResponse>('/api/xdr-defense/rollback/confirm', {
        method: 'POST',
        body: JSON.stringify({
          agent_id: rollbackAgentId,
          incident_id: rollbackIncidentId,
          reason: rollbackReason || undefined,
        }),
      });
      setLastActionResult(response as unknown as Record<string, unknown>);
      notifications.toasts.addSuccess('Rollback confirmation sent');
      setRollbackAgentId('');
      setRollbackIncidentId('');
      setRollbackReason('');
    } catch (error) {
      toastError('Unable to confirm rollback', error);
    } finally {
      setIsConfirmingRollback(false);
    }
  };

  const retryRolloutAgents = async (agentIDs?: string[]) => {
    setIsRetryingRollout(true);
    try {
      const encodedPolicyID = encodeURIComponent(selectedManagerPolicyID);
      const rollout = await api<PolicyRolloutResponse>(
        `/api/xdr-defense/policy-rollouts/${encodedPolicyID}/retry`,
        {
          method: 'POST',
          body: JSON.stringify({ agent_ids: agentIDs && agentIDs.length > 0 ? agentIDs : undefined }),
        }
      );
      setLatestRollout(rollout);
      setSelectedRetryAgentIDs([]);
      notifications.toasts.addSuccess(
        agentIDs && agentIDs.length > 0
          ? `Retry requested for ${agentIDs.length} pending agent(s)`
          : 'Retry requested for all pending agents'
      );
    } catch (error) {
      toastError('Unable to request rollout retry', error);
    } finally {
      setIsRetryingRollout(false);
    }
  };

  const retryYaraRolloutFailures = async () => {
    setIsRetryingYaraRollout(true);
    try {
      const encodedPolicyID = encodeURIComponent(selectedManagerPolicyID || 'default');
      const rollout = await api<YaraRolloutSummaryResponse>(
        `/api/xdr-defense/yara-rollouts/${encodedPolicyID}/retry`,
        {
          method: 'POST',
          body: JSON.stringify({}),
        }
      );
      setLatestYaraRollout(rollout);
      notifications.toasts.addSuccess('Retry requested for YARA rollout failures');
    } catch (error) {
      toastError('Unable to retry YARA rollout failures', error);
    } finally {
      setIsRetryingYaraRollout(false);
    }
  };

  const tabs = [
    { id: 'overview', name: 'Overview' },
    { id: 'policy', name: 'Policy' },
    { id: 'artifacts', name: 'Detection Content' },
    { id: 'threatIntel', name: 'Threat Intel' },
    { id: 'response', name: 'Response' },
  ] as const;

  const manifestArtifactIDs = useMemo(() => {
    const entries = manifest?.artifacts ?? [];
    return new Set(
      entries
        .map((entry) => (typeof entry.id === 'string' ? entry.id : ''))
        .filter((value) => value.length > 0)
    );
  }, [manifest]);

  const artifactTypeSummaries = useMemo(
    () =>
      artifactTypeOptions.map((typeOption) => {
        const type = typeOption.value as ArtifactType;
        const byType = artifacts.filter((artifact) => artifact.type === type);
        const active = byType.filter((artifact) => artifact.enabled).length;
        const inUse = byType.filter((artifact) => manifestArtifactIDs.has(artifact.id)).length;
        return {
          type,
          label: typeOption.text,
          total: byType.length,
          active,
          inUse,
        };
      }),
    [artifacts, manifestArtifactIDs]
  );

  const selectedArtifact = useMemo(
    () => artifacts.find((artifact) => artifact.id === selectedArtifactID) ?? null,
    [artifacts, selectedArtifactID]
  );

  const selectedArtifactYaraRuleNames = useMemo(() => {
    if (!selectedArtifact || selectedArtifact.type !== 'yara') {
      return null;
    }

    const explicitMatch = yaraRuleCatalogByArtifactID[selectedArtifact.id];
    if (explicitMatch) {
      return explicitMatch;
    }

    const artifactID = selectedArtifact.id.toLowerCase();
    if (artifactID.startsWith('yara-forge-')) {
      const derivedName = artifactID
        .replace(/^yara-forge-/, '')
        .split('-')
        .filter((segment) => segment.length > 0)
        .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
        .join(' ');
      return [derivedName];
    }
    if (artifactID.includes('play') && artifactID.includes('esxi')) {
      return ['Detecting Play Ransomware on ESXi Hypervisors'];
    }
    if (artifactID.includes('erlang') || artifactID.includes('otp')) {
      return ['Detecting Vulnerable Erlang/OTP SSH Binaries'];
    }

    return [];
  }, [selectedArtifact]);

  const artifactColumns = useMemo(
    (): EuiBasicTableColumn<ArtifactEntry>[] => [
      { field: 'id', name: 'Artifact' },
      { field: 'type', name: 'Type' },
      {
        field: 'enabled',
        name: 'State',
        render: (enabled: boolean) => (
          <EuiBadge color={enabled ? 'secondary' : 'default'}>{enabled ? 'active' : 'inactive'}</EuiBadge>
        ),
      },
      {
        name: `In use (${selectedManagerPolicyID})`,
        render: (artifact: ArtifactEntry) => (
          <EuiBadge color={manifestArtifactIDs.has(artifact.id) ? 'accent' : 'hollow'}>
            {manifestArtifactIDs.has(artifact.id) ? 'yes' : 'no'}
          </EuiBadge>
        ),
      },
      { field: 'version', name: 'Version' },
      {
        field: 'checksum',
        name: 'Checksum',
        render: (value: string) => <span className="xdrDefense__truncate">{value}</span>,
      },
      {
        field: 'updatedAt',
        name: 'Updated',
        render: (value: string) => prettyDate(value),
      },
    ],
    [manifestArtifactIDs, selectedManagerPolicyID]
  );

  const pagedArtifacts = useMemo(() => {
    const start = artifactPageIndex * artifactPageSize;
    return artifacts.slice(start, start + artifactPageSize);
  }, [artifacts, artifactPageIndex, artifactPageSize]);

  const artifactSelection = useMemo(() => {
    const pageArtifactIDs = new Set(pagedArtifacts.map((artifact) => artifact.id));
    const selectedOnPage = pagedArtifacts.filter((artifact) => selectedArtifactIDs.includes(artifact.id));

    return {
      initialSelected: selectedOnPage,
      onSelectionChange: (selection: ArtifactEntry[]) => {
        const selectedIDSet = new Set(selection.map((artifact) => artifact.id));
        setSelectedArtifactIDs((current) => {
          const next = current.filter((artifactID) => !pageArtifactIDs.has(artifactID));
          selection.forEach((artifact) => {
            if (!next.includes(artifact.id)) {
              next.push(artifact.id);
            }
          });
          return next;
        });

        if (selection.length > 0) {
          const lastSelected = selection[selection.length - 1];
          if (lastSelected && selectedIDSet.has(lastSelected.id)) {
            setSelectedArtifactID(lastSelected.id);
          }
        }
      },
    };
  }, [pagedArtifacts, selectedArtifactIDs]);

  const artifactPagination = useMemo(
    () => ({
      pageIndex: artifactPageIndex,
      pageSize: artifactPageSize,
      pageSizeOptions: [20, 50, 100, 500],
      totalItemCount: artifacts.length,
    }),
    [artifactPageIndex, artifactPageSize, artifacts.length]
  );

  const onArtifactTableChange = ({ page }: CriteriaWithPagination<ArtifactEntry>) => {
    if (!page) {
      return;
    }

    setArtifactPageIndex(page.index);
    setArtifactPageSize(page.size);
  };

  const feedColumns = useMemo(
    (): EuiBasicTableColumn<ThreatFeedEntry>[] => [
      { field: 'name', name: 'Feed' },
      { field: 'type', name: 'Type' },
      {
        field: 'enabled',
        name: 'State',
        render: (value: boolean) => <EuiBadge color={value ? 'secondary' : 'default'}>{value ? 'enabled' : 'disabled'}</EuiBadge>,
      },
      {
        field: 'lastSyncAt',
        name: 'Last sync',
        render: (value?: string) => prettyDate(value),
      },
      {
        name: 'Actions',
        field: 'id',
        actions: [
          {
            name: 'Sync',
            description: 'Sync feed into a local threatintel artifact',
            onClick: (item: ThreatFeedEntry) => syncFeed(item.id),
            type: 'icon',
            icon: 'refresh',
          },
        ],
      },
    ],
    []
  );

  const rolloutRows = useMemo((): RolloutTableRow[] => {
    if (!latestRollout) {
      return [];
    }

    const managerAgentByID = managerAgents.reduce<Record<string, ManagerAgent>>((acc, agent) => {
      acc[agent.id] = agent;
      return acc;
    }, {});
    const ackedByID = latestRollout.acked_agents.reduce<Record<string, { hostname?: string }>>((acc, ack) => {
      acc[ack.agent_id] = { hostname: ack.hostname };
      return acc;
    }, {});

    return latestRollout.target_agent_ids.map((agentID) => {
      const managerAgent = managerAgentByID[agentID];
      const ack = ackedByID[agentID];
      const isAcked = latestRollout.acked_agent_ids.includes(agentID);
      return {
        id: agentID,
        agentID,
        agentName: managerAgent?.name || ack?.hostname || 'unknown',
        status: isAcked ? 'acked' : 'pending',
        lastRetryRequested: prettyDate(latestRollout.retry_requested_at[agentID]),
      };
    });
  }, [latestRollout, managerAgents]);

  const pendingRolloutAgentIDs = useMemo(
    () => rolloutRows.filter((row) => row.status === 'pending').map((row) => row.agentID),
    [rolloutRows]
  );

  const rolloutColumns = useMemo(
    (): EuiBasicTableColumn<RolloutTableRow>[] => [
      { field: 'agentID', name: 'Agent ID' },
      { field: 'agentName', name: 'Hostname / Name' },
      {
        field: 'status',
        name: 'Status',
        render: (value: RolloutTableRow['status']) => (
          <EuiBadge color={value === 'acked' ? 'secondary' : 'warning'}>{value}</EuiBadge>
        ),
      },
      {
        field: 'lastRetryRequested',
        name: 'Last retry requested',
      },
    ],
    []
  );

  const yaraRolloutFailureRows = useMemo((): YaraRolloutFailureRow[] => {
    if (!latestYaraRollout) {
      return [];
    }

    const managerAgentByID = managerAgents.reduce<Record<string, ManagerAgent>>((acc, agent) => {
      acc[agent.id] = agent;
      return acc;
    }, {});
    const staleSet = new Set(latestYaraRollout.stale_pending_agent_ids);

    return latestYaraRollout.agents
      .filter((agent) => agent.state === 'failed' || staleSet.has(agent.agent_id))
      .map((agent) => {
        const managerAgent = managerAgentByID[agent.agent_id];
        const stalePending = staleSet.has(agent.agent_id);
        return {
          id: `${agent.agent_id}:${agent.last_action}`,
          agentID: agent.agent_id,
          agentName: managerAgent?.name || agent.hostname || 'unknown',
          action: agent.last_action,
          failureType: stalePending ? ('stale_pending' as const) : ('ack_failed' as const),
          details: stalePending
            ? `No ack past ${latestYaraRollout.stale_after_seconds}s (offline/no-ack).`
            : agent.failure_reason || 'Agent reported failure while applying action.',
          lastAttemptedAt: prettyDate(agent.retry_requested_at || agent.last_attempted_at),
        };
      })
      .sort((a, b) => a.agentID.localeCompare(b.agentID));
  }, [latestYaraRollout, managerAgents]);

  const yaraRolloutFailureColumns = useMemo(
    (): EuiBasicTableColumn<YaraRolloutFailureRow>[] => [
      { field: 'agentID', name: 'Agent ID' },
      { field: 'agentName', name: 'Hostname / Name' },
      {
        field: 'action',
        name: 'Action',
        render: (value: YaraRolloutAction) => <EuiBadge color="hollow">{value}</EuiBadge>,
      },
      {
        field: 'failureType',
        name: 'Failure',
        render: (value: YaraRolloutFailureRow['failureType']) => (
          <EuiBadge color={value === 'stale_pending' ? 'warning' : 'danger'}>
            {value === 'stale_pending' ? 'offline/no-ack stale pending' : 'ack failed'}
          </EuiBadge>
        ),
      },
      { field: 'details', name: 'Details' },
      { field: 'lastAttemptedAt', name: 'Last attempt / retry' },
    ],
    []
  );

  const renderOverview = () => {
    if (!summary) {
      return <EuiEmptyPrompt title={<h2>Loading summary</h2>} body="Waiting for control-plane data." />;
    }

    return (
      <>
        <EuiFlexGrid columns={4} gutterSize="m">
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={
                <EuiStat
                  title={`v${summary.policy.version} · ${summary.policy.mode}`}
                  description="Latest posture"
                  titleColor="primary"
                />
              }
              description={`Current defense posture for manager policy ${selectedManagerPolicyID}.`}
            />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={
                <EuiStat
                  title={`${latestRollout?.acked_agent_ids.length ?? 0}/${latestRollout?.target_agent_ids.length ?? 0}`}
                  description="Rollout health"
                  titleColor={(latestRollout?.pending_agent_ids.length ?? 0) > 0 ? 'warning' : 'secondary'}
                />
              }
              description={`Acked / target agents, pending: ${latestRollout?.pending_agent_ids.length ?? 0}.`}
            />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={
                <EuiStat
                  title={`${capabilities['prevention.enabled'] ? 'prevent' : 'detect'} / ${
                    capabilities['memory.fileless'] ? 'fileless on' : 'fileless off'
                  }`}
                  description="Risk indicators"
                  titleColor={capabilities['prevention.enabled'] ? 'danger' : 'subdued'}
                />
              }
              description="Quick posture signal from prevention state and memory.fileless coverage."
            />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={
                <EuiStat title={`${summary.artifact_count} / ${summary.feed_count}`} description="Artifacts / Feeds" titleColor="accent" />
              }
              description="Operational content inventory backing endpoint detections and intel updates."
            />
          </EuiFlexItem>
        </EuiFlexGrid>

        <EuiSpacer size="l" />

        <EuiFlexGroup gutterSize="l" alignItems="stretch">
          <EuiFlexItem grow={2}>
            <EuiPanel paddingSize="l" className="xdrDefense__heroPanel">
              <EuiTitle size="m">
                <h3>Defense control plane</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <EuiText color="subdued">
                <p>
                  `xdr-defense` manages local artifact promotion, agent-side detect versus prevent mode, and the
                  OpenSearch assets needed for time-window correlation and rollback workflows.
                </p>
              </EuiText>
              <EuiSpacer size="m" />
              <EuiFlexGroup gutterSize="m">
                <EuiFlexItem grow={false}>
                  <EuiHealth color={summary.rollback_enabled ? 'success' : 'subdued'}>
                    Rollback {summary.rollback_enabled ? 'enabled' : 'disabled'}
                  </EuiHealth>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiHealth color={capabilities['correlation.enabled'] ? 'success' : 'warning'}>
                    Correlation {capabilities['correlation.enabled'] ? 'enabled' : 'disabled'}
                  </EuiHealth>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel paddingSize="l" className="xdrDefense__sidePanel">
              <EuiTitle size="xs">
                <h4>Quick actions</h4>
              </EuiTitle>
              <EuiSpacer size="m" />
              <EuiButton fill onClick={() => setActiveTab('policy')} fullWidth>
                Tune policy
              </EuiButton>
              <EuiSpacer size="s" />
              <EuiButton onClick={() => setActiveTab('artifacts')} fullWidth>
                Manage detection content
              </EuiButton>
              <EuiSpacer size="s" />
              <EuiButtonEmpty onClick={() => setActiveTab('threatIntel')}>
                Manage feeds
              </EuiButtonEmpty>
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size="l" />

        <EuiFlexGroup gutterSize="l">
          <EuiFlexItem>
            <EuiPanel paddingSize="l">
              <EuiTitle size="xs">
                <h4>Latest manifest</h4>
              </EuiTitle>
              <EuiSpacer size="m" />
              <EuiCodeBlock language="json" overflowHeight={260} isCopyable>
                {JSON.stringify(manifest, null, 2)}
              </EuiCodeBlock>
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel paddingSize="l">
              <EuiTitle size="xs">
                <h4>Correlation content</h4>
              </EuiTitle>
              <EuiSpacer size="m" />
              {correlationRules.map((rule) => (
                <EuiPanel key={rule.id} color="subdued" paddingSize="m" className="xdrDefense__ruleCard">
                  <EuiText size="s">
                    <strong>{rule.name}</strong>
                  </EuiText>
                  <EuiText size="s" color="subdued">
                    <p>{rule.id}</p>
                  </EuiText>
                </EuiPanel>
              ))}
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>
      </>
    );
  };

  const renderPolicy = () => (
    <EuiFlexGroup gutterSize="l" alignItems="flexStart">
      <EuiFlexItem grow={2}>
        <EuiPanel paddingSize="l">
          <EuiCallOut title="Policy lifecycle remains in xdr-manager-plugin" color="primary" iconType="iInCircle">
            <p>
              Create, delete, and agent assignment for manager policies are owned by `xdr-manager-plugin`. This tab only
              controls detect/prevent mode and capability toggles for the selected manager policy.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          <EuiCompressedFormRow label="Manager policy">
            <EuiCompressedSelect
              value={selectedManagerPolicyID}
              options={
                managerPolicies.length > 0
                  ? managerPolicies.map((policy) => ({ value: policy.id, text: `${policy.name} (${policy.id})` }))
                  : [{ value: 'default', text: 'default (fallback defense posture)' }]
              }
              onChange={(event) => setSelectedManagerPolicyID(event.target.value)}
            />
          </EuiCompressedFormRow>
          <EuiSpacer size="m" />
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
            <EuiFlexItem grow={false}>
              <EuiTitle size="m">
                <h3>Defense Posture</h3>
              </EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton fill isLoading={isSavingPolicy} onClick={savePolicy}>
                Save defense posture
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          <EuiCompressedFormRow label="Mode for selected manager policy">
            <EuiCompressedSelect
              value={mode}
              options={[
                { value: 'detect', text: 'Detect' },
                { value: 'prevent', text: 'Prevent' },
              ]}
              onChange={(event) => setMode(event.target.value as PolicyMode)}
            />
          </EuiCompressedFormRow>
          <EuiSpacer size="m" />
          {capabilityGroups.map((group) => (
            <EuiPanel key={group.title} color="subdued" paddingSize="m" className="xdrDefense__groupPanel">
              <EuiTitle size="xs">
                <h4>{group.title}</h4>
              </EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued">
                <p>{group.description}</p>
              </EuiText>
              <EuiSpacer size="m" />
              {group.keys.map((key) => (
                <EuiCompressedSwitch
                  key={key}
                  label={key}
                  checked={Boolean(capabilities[key])}
                  onChange={(event) => toggleCapability(key, event.target.checked)}
                />
              ))}
            </EuiPanel>
          ))}
          <EuiSpacer size="m" />
          <EuiTitle size="xs">
            <h4>Manager policy coverage</h4>
          </EuiTitle>
          <EuiSpacer size="s" />
          <EuiBasicTable
            items={managerPolicies}
            columns={[
              { field: 'name', name: 'Policy name' },
              { field: 'id', name: 'Policy ID' },
              {
                name: 'Defense mode',
                render: (item: ManagerPolicy) => policyOverlays[item.id]?.mode ?? 'detect',
              },
            ]}
          />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="l">
          <EuiTitle size="xs">
            <h4>Design intent</h4>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiCallOut title="Agent-side detections stay local" color="primary" iconType="securitySignalDetected">
            <p>
              Malware, behavioral, and memory signals stay on the endpoint for single-event detection. OpenSearch handles
              the time-window correlations and policy distribution.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          <EuiText size="s">
            <p>
              Use `prevent` only when you are ready to enforce kill, block, quarantine, or rollback workflows for this
              specific manager policy. Detect mode keeps the same telemetry and alerting path without agent-side blocking.
            </p>
          </EuiText>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );

  const renderArtifacts = () => {
    const activeCount = artifacts.filter((artifact) => artifact.enabled).length;
    const inUseCount = artifacts.filter((artifact) => manifestArtifactIDs.has(artifact.id)).length;

    return (
      <>
        <EuiPanel paddingSize="l">
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
            <EuiFlexItem grow={false}>
              <EuiTitle size="m">
                <h3>Detection content registry</h3>
              </EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
                <EuiFlexItem grow={false}>
                  <EuiButton size="s" isLoading={isSyncingYaraForge} onClick={syncYaraForgeCore}>
                    {isSyncingYaraForge
                      ? `Syncing YARA Forge Core${
                          yaraForgeSyncStatus?.total_rules
                            ? ` (${yaraForgeSyncStatus.processed_rules ?? 0}/${yaraForgeSyncStatus.total_rules})`
                            : ''
                        }`
                      : 'Sync YARA Forge Core'}
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty size="s" onClick={() => setIsCustomContentDrawerOpen(true)}>
                    Add custom content
                  </EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiBadge color="hollow">{artifacts.length} total</EuiBadge>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiBadge color="secondary">{activeCount} active</EuiBadge>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiBadge color="accent">{inUseCount} in use</EuiBadge>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>

          <EuiSpacer size="m" />

          <EuiFlexGrid columns={2} gutterSize="m">
            {artifactTypeSummaries.map((entry) => (
              <EuiFlexItem key={entry.type}>
                <EuiPanel color="subdued" paddingSize="m">
                  <EuiText size="s">
                    <strong>{entry.label}</strong>
                  </EuiText>
                  <EuiSpacer size="s" />
                  <EuiFlexGroup gutterSize="s" responsive={false}>
                    <EuiFlexItem grow={false}>
                      <EuiBadge color="hollow">total {entry.total}</EuiBadge>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiBadge color="secondary">active {entry.active}</EuiBadge>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiBadge color="accent">in use {entry.inUse}</EuiBadge>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                </EuiPanel>
              </EuiFlexItem>
            ))}
          </EuiFlexGrid>

          <EuiSpacer size="m" />

          {isSyncingYaraForge && (
            <>
              <EuiText size="s" color="subdued">
                <p>
                  YARA Forge sync in progress: {yaraForgeSyncStatus?.status ?? 'starting'}
                  {typeof yaraForgeSyncStatus?.processed_rules === 'number'
                    ? `, processed ${yaraForgeSyncStatus.processed_rules}`
                    : ''}
                  {typeof yaraForgeSyncStatus?.total_rules === 'number'
                    ? ` of ${yaraForgeSyncStatus.total_rules}`
                    : ''}
                  . New rules will appear as they are imported.
                </p>
              </EuiText>
              <EuiSpacer size="s" />
            </>
          )}

          <EuiFlexGroup gutterSize="l" alignItems="flexStart">
            <EuiFlexItem grow={2} style={{ minWidth: 0 }}>
              <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiText size="s" color="subdued">
                    <p>{selectedArtifactIDs.length} selected</p>
                  </EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
                    <EuiFlexItem grow={false}>
                      <EuiButton
                        size="s"
                        onClick={() => updateSelectedArtifactsState(true)}
                        isDisabled={selectedArtifactIDs.length === 0 || bulkArtifactOperation !== null}
                        isLoading={bulkArtifactOperation === 'activate'}
                      >
                        Activate
                      </EuiButton>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiButton
                        size="s"
                        onClick={() => updateSelectedArtifactsState(false)}
                        isDisabled={selectedArtifactIDs.length === 0 || bulkArtifactOperation !== null}
                        isLoading={bulkArtifactOperation === 'deactivate'}
                      >
                        Deactivate
                      </EuiButton>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiButton
                        size="s"
                        color="danger"
                        onClick={deleteSelectedArtifacts}
                        isDisabled={selectedArtifactIDs.length === 0 || bulkArtifactOperation !== null}
                        isLoading={bulkArtifactOperation === 'delete'}
                      >
                        Delete
                      </EuiButton>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                </EuiFlexItem>
              </EuiFlexGroup>

              <EuiSpacer size="s" />

              <div style={{ overflowX: 'auto', width: '100%', paddingBottom: 4 }}>
                <div style={{ minWidth: 860 }}>
                  <EuiBasicTable
                    itemId="id"
                    items={pagedArtifacts}
                    columns={artifactColumns}
                    selection={artifactSelection}
                    pagination={artifactPagination}
                    onChange={onArtifactTableChange}
                    rowProps={(artifact) => ({
                      onClick: () => setSelectedArtifactID(artifact.id),
                      style: { cursor: 'pointer' },
                      'aria-selected': selectedArtifactID === artifact.id,
                    })}
                  />
                </div>
              </div>
            </EuiFlexItem>

            <EuiFlexItem grow={false} className="xdrDefense__artifactDetailsItem">
              <EuiPanel color="subdued" paddingSize="m" className="xdrDefense__artifactDetailsPanel">
                <EuiTitle size="xs">
                  <h4>Selected artifact details</h4>
                </EuiTitle>
                <EuiSpacer size="s" />
                {!selectedArtifact ? (
                  <EuiText size="s" color="subdued">
                    <p>Select an artifact row to inspect metadata and embedded rule details.</p>
                  </EuiText>
                ) : (
                  <>
                    <EuiText size="s">
                      <p>
                        <strong>Artifact ID:</strong> {selectedArtifact.id}
                      </p>
                      <p>
                        <strong>Type:</strong> {selectedArtifact.type}
                      </p>
                      <p>
                        <strong>State:</strong> {selectedArtifact.enabled ? 'active' : 'inactive'}
                      </p>
                      <p>
                        <strong>Version:</strong> {selectedArtifact.version}
                      </p>
                      <p>
                        <strong>Checksum:</strong> {selectedArtifact.checksum}
                      </p>
                      <p>
                        <strong>Description:</strong> {selectedArtifact.description || 'n/a'}
                      </p>
                      <p>
                        <strong>Source URL:</strong>{' '}
                        {selectedArtifact.sourceUrl ? (
                          <EuiLink href={selectedArtifact.sourceUrl} target="_blank" external>
                            {selectedArtifact.sourceUrl}
                          </EuiLink>
                        ) : (
                          'n/a'
                        )}
                      </p>
                    </EuiText>

                    {selectedArtifact.type === 'yara' && (
                      <>
                        <EuiSpacer size="s" />
                        <EuiTitle size="xxs">
                          <h5>Embedded YARA rule names</h5>
                        </EuiTitle>
                        <EuiSpacer size="xs" />
                        {selectedArtifactYaraRuleNames && selectedArtifactYaraRuleNames.length > 0 ? (
                          <EuiText size="s">
                            <ul>
                              {selectedArtifactYaraRuleNames.map((ruleName) => (
                                <li key={ruleName}>{ruleName}</li>
                              ))}
                            </ul>
                          </EuiText>
                        ) : (
                          <EuiText size="s" color="subdued">
                            <p>No embedded rule catalog available for this artifact yet.</p>
                          </EuiText>
                        )}
                      </>
                    )}
                  </>
                )}
              </EuiPanel>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPanel>

        <EuiSpacer size="l" />

        <EuiPanel paddingSize="l">
          <EuiTitle size="xs">
            <h4>YARA rollout failures</h4>
          </EuiTitle>
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiBadge color={yaraRolloutFailureRows.length > 0 ? 'warning' : 'secondary'}>
                failures {yaraRolloutFailureRows.length}
              </EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiBadge color="hollow">
                rollout v{latestYaraRollout?.rollout_version ?? 0}
              </EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton
                size="s"
                onClick={retryYaraRolloutFailures}
                isLoading={isRetryingYaraRollout}
                isDisabled={yaraRolloutFailureRows.length === 0}
              >
                Retry all failures
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          {yaraRolloutFailureRows.length === 0 ? (
            <EuiText size="s" color="subdued">
              <p>No ack failures or stale pending agents for the latest YARA rollout.</p>
            </EuiText>
          ) : (
            <EuiBasicTable
              items={yaraRolloutFailureRows}
              columns={yaraRolloutFailureColumns}
            />
          )}
        </EuiPanel>
      </>
    );
  };

  const renderThreatIntel = () => (
    <EuiFlexGroup gutterSize="l" alignItems="flexStart">
      <EuiFlexItem grow={2}>
        <EuiPanel paddingSize="l">
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
            <EuiFlexItem grow={false}>
              <EuiTitle size="m">
                <h3>Threat intel sources</h3>
              </EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty onClick={loadData}>Refresh</EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          <EuiBasicTable items={feeds} columns={feedColumns} />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="l">
          <EuiTitle size="xs">
            <h4>Add feed</h4>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiCompressedFormRow label="Feed ID">
            <EuiCompressedFieldText value={feedId} onChange={(event) => setFeedId(event.target.value)} />
          </EuiCompressedFormRow>
          <EuiCompressedFormRow label="Name">
            <EuiCompressedFieldText value={feedName} onChange={(event) => setFeedName(event.target.value)} />
          </EuiCompressedFormRow>
          <EuiCompressedFormRow label="Type">
            <EuiCompressedSelect value={feedType} options={feedTypeOptions} onChange={(event) => setFeedType(event.target.value as FeedType)} />
          </EuiCompressedFormRow>
          <EuiCompressedFormRow label="Feed URL">
            <EuiCompressedFieldText value={feedUrl} onChange={(event) => setFeedUrl(event.target.value)} />
          </EuiCompressedFormRow>
          <EuiSpacer size="m" />
          <EuiButton fill fullWidth isLoading={isSavingFeed} onClick={saveFeed}>
            Save feed
          </EuiButton>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );

  const renderResponse = () => (
    <EuiFlexGroup gutterSize="l" alignItems="flexStart">
      <EuiFlexItem>
        <EuiPanel paddingSize="l">
          <EuiTitle size="m">
            <h3>Rollback confirmation</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <EuiText color="subdued" size="s">
            <p>
              Use this when a ransomware incident has been validated and the endpoint is allowed to restore tracked files
              from the rollback journal.
            </p>
          </EuiText>
          <EuiSpacer size="m" />
          <EuiCompressedFormRow label="Agent ID">
            <EuiCompressedFieldText value={rollbackAgentId} onChange={(event) => setRollbackAgentId(event.target.value)} />
          </EuiCompressedFormRow>
          <EuiCompressedFormRow label="Incident ID">
            <EuiCompressedFieldText value={rollbackIncidentId} onChange={(event) => setRollbackIncidentId(event.target.value)} />
          </EuiCompressedFormRow>
          <EuiCompressedFormRow label="Reason">
            <EuiCompressedFieldText value={rollbackReason} onChange={(event) => setRollbackReason(event.target.value)} />
          </EuiCompressedFormRow>
          <EuiSpacer size="m" />
          <EuiButton color="danger" fill isLoading={isConfirmingRollback} onClick={confirmRollback}>
            Confirm rollback
          </EuiButton>
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="l">
          <EuiTitle size="xs">
            <h4>Last action result</h4>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiCodeBlock language="json" overflowHeight={300} isCopyable>
            {JSON.stringify(lastActionResult ?? { status: 'No response action executed yet.' }, null, 2)}
          </EuiCodeBlock>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );

  const renderPolicyRolloutPanel = () => {
    if (!latestRollout) {
      return (
        <EuiPanel paddingSize="l">
          <EuiTitle size="xs">
            <h4>Latest rollout tracking</h4>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiEmptyPrompt
            title={<h2>No rollout data yet</h2>}
            body="Save a defense posture to create rollout tracking for the selected manager policy."
          />
        </EuiPanel>
      );
    }

    return (
      <EuiPanel paddingSize="l">
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m">
          <EuiFlexItem grow={false}>
            <EuiTitle size="xs">
              <h4>Latest rollout tracking</h4>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiBadge color="hollow">posture v{latestRollout.posture_version}</EuiBadge>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiBadge color={(latestRollout.pending_agent_ids.length ?? 0) > 0 ? 'warning' : 'secondary'}>
                  pending {latestRollout.pending_agent_ids.length}
                </EuiBadge>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFlexGroup gutterSize="s" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButton
                  size="s"
                  isLoading={isRetryingRollout}
                  onClick={() => retryRolloutAgents(selectedRetryAgentIDs)}
                  isDisabled={selectedRetryAgentIDs.length === 0}
                >
                  Retry selected
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton
                  size="s"
                  onClick={() => retryRolloutAgents()}
                  isLoading={isRetryingRollout}
                  isDisabled={pendingRolloutAgentIDs.length === 0}
                >
                  Retry all pending
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size="m" />
        <EuiBasicTable
          itemId="id"
          items={rolloutRows}
          columns={rolloutColumns}
          selection={{
            selectable: (item: RolloutTableRow) => item.status === 'pending',
            onSelectionChange: (selection: RolloutTableRow[]) => {
              setSelectedRetryAgentIDs(selection.map((item) => item.agentID));
            },
          }}
        />
      </EuiPanel>
    );
  };

  return (
    <EuiPageTemplate
      grow
      restrictWidth={false}
      className="xdrDefense"
      pageHeader={{
        pageTitle: 'XDR Defense',
        description:
          'Policy, artifact, prevention, and threat-intel management for the xdr-agent control plane.',
        rightSideItems: [
          <EuiButton key="refresh" onClick={loadData} isLoading={isLoading}>
            Refresh
          </EuiButton>,
        ],
      }}
    >
      <EuiTabs>
        {tabs.map((tab) => (
          <EuiTab
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            isSelected={activeTab === tab.id}
          >
            {tab.name}
          </EuiTab>
        ))}
      </EuiTabs>

      <EuiSpacer size="l" />

      {activeTab === 'overview' && renderOverview()}
      {activeTab === 'policy' && renderPolicy()}
      {activeTab === 'artifacts' && renderArtifacts()}
      {activeTab === 'threatIntel' && renderThreatIntel()}
      {activeTab === 'response' && renderResponse()}

      {activeTab === 'policy' && (
        <>
          <EuiHorizontalRule margin="xl" />
          {renderPolicyRolloutPanel()}
        </>
      )}

      {isCustomContentDrawerOpen && (
        <EuiFlyout onClose={() => setIsCustomContentDrawerOpen(false)} ownFocus size="m" aria-labelledby="xdrDefenseCustomContentDrawerTitle">
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size="m">
              <h2 id="xdrDefenseCustomContentDrawerTitle">Add custom content</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                Publish curated custom rules and hash sets. YARA Forge content continues to be managed by sync.
              </p>
            </EuiText>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <EuiCompressedFormRow label="Artifact ID">
              <EuiCompressedFieldText value={artifactId} onChange={(event) => setArtifactId(event.target.value)} />
            </EuiCompressedFormRow>
            <EuiCompressedFormRow label="Type">
              <EuiCompressedSelect
                value={artifactType}
                options={artifactTypeOptions}
                onChange={(event) => setArtifactType(event.target.value as ArtifactType)}
              />
            </EuiCompressedFormRow>
            <EuiCompressedFormRow label="Version">
              <EuiCompressedFieldText value={artifactVersion} onChange={(event) => setArtifactVersion(event.target.value)} />
            </EuiCompressedFormRow>
            <EuiCompressedFormRow label="Checksum">
              <EuiCompressedFieldText value={artifactChecksum} onChange={(event) => setArtifactChecksum(event.target.value)} />
            </EuiCompressedFormRow>
            <EuiCompressedFormRow label="Source URL">
              <EuiCompressedFieldText value={artifactSourceUrl} onChange={(event) => setArtifactSourceUrl(event.target.value)} />
            </EuiCompressedFormRow>
            <EuiCompressedFormRow label="Description">
              <EuiCompressedFieldText value={artifactDescription} onChange={(event) => setArtifactDescription(event.target.value)} />
            </EuiCompressedFormRow>
          </EuiFlyoutBody>
          <EuiFlyoutFooter>
            <EuiFlexGroup justifyContent="flexEnd" gutterSize="s" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty onClick={() => setIsCustomContentDrawerOpen(false)}>Cancel</EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton fill isLoading={isSavingArtifact} onClick={saveArtifact}>
                  Publish custom content
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutFooter>
        </EuiFlyout>
      )}
    </EuiPageTemplate>
  );
};
