import React, { useEffect, useMemo, useState } from 'react';
import {
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
  EuiFlexGrid,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiHorizontalRule,
  EuiPageTemplate,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { i18n } from '@osd/i18n';
import { CoreStart } from '../../../../src/core/public';

type PolicyMode = 'detect' | 'prevent';
type ArtifactType = 'yara' | 'behavioral' | 'hashes' | 'threatintel';
type FeedType = 'hashes' | 'domain' | 'ip' | 'url';
type TabId = 'overview' | 'policy' | 'artifacts' | 'threatIntel' | 'response';

interface DefensePolicy {
  mode: PolicyMode;
  capabilities: Record<string, boolean>;
  updatedAt: string;
  version: number;
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
  updatedAt: string;
  sourceUrl?: string;
  description?: string;
}

interface ArtifactListResponse {
  artifacts: ArtifactEntry[];
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
  const [isConfirmingRollback, setIsConfirmingRollback] = useState(false);

  const [mode, setMode] = useState<PolicyMode>('detect');
  const [capabilities, setCapabilities] = useState<Record<string, boolean>>({});

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

  const api = async <T,>(path: string, init?: { method?: string; body?: string }): Promise<T> => {
    if (!init?.method || init.method === 'GET') {
      return http.get<T>(path);
    }
    return http.fetch<T>(path, {
      method: init.method,
      body: init.body,
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

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [summaryResponse, artifactResponse, feedResponse, manifestResponse, correlationResponse] =
        await Promise.all([
          api<SummaryResponse>('/api/xdr-defense/summary'),
          api<ArtifactListResponse>('/api/xdr-defense/artifacts'),
          api<ThreatFeedListResponse>('/api/xdr-defense/threat-intel/feeds'),
          api<ManifestResponse>('/api/xdr-defense/artifacts/manifest/latest'),
          api<CorrelationRuleResponse>('/api/xdr-defense/correlation-rules'),
        ]);
      setSummary(summaryResponse);
      setArtifacts(artifactResponse.artifacts);
      setFeeds(feedResponse.feeds);
      setManifest(manifestResponse);
      setCorrelationRules(correlationResponse.rules);
      setMode(summaryResponse.policy.mode);
      setCapabilities(summaryResponse.policy.capabilities);
    } catch (error) {
      toastError('Unable to load XDR Defense data', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const toggleCapability = (key: string, value: boolean) => {
    setCapabilities((current) => ({ ...current, [key]: value }));
  };

  const savePolicy = async () => {
    setIsSavingPolicy(true);
    try {
      const response = await api<DefensePolicy>('/api/xdr-defense/policy', {
        method: 'PUT',
        body: JSON.stringify({ mode, capabilities }),
      });
      setLastActionResult(response as unknown as Record<string, unknown>);
      notifications.toasts.addSuccess('Policy updated');
      await loadData();
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
      await loadData();
    } catch (error) {
      toastError('Unable to save artifact', error);
    } finally {
      setIsSavingArtifact(false);
    }
  };

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

  const tabs = [
    { id: 'overview', name: 'Overview' },
    { id: 'policy', name: 'Policy' },
    { id: 'artifacts', name: 'Artifacts' },
    { id: 'threatIntel', name: 'Threat Intel' },
    { id: 'response', name: 'Response' },
  ] as const;

  const artifactColumns = useMemo(
    (): EuiBasicTableColumn<ArtifactEntry>[] => [
      { field: 'id', name: 'Artifact' },
      { field: 'type', name: 'Type' },
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
    []
  );

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
              title={<EuiStat title={summary.policy.mode} description="Mode" titleColor="primary" />}
              description="Global behavior toggle for agent-side detection versus prevention."
            />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={<EuiStat title={summary.artifact_count} description="Artifacts" titleColor="accent" />}
              description="Versioned content packages prepared for agent rollout."
            />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={<EuiStat title={summary.feed_count} description="Feeds" titleColor="secondary" />}
              description="Threat-intel sources curated here and distributed locally to agents."
            />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard
              className="xdrDefense__metricCard"
              title={
                <EuiStat
                  title={summary.prevention_enabled ? 'armed' : 'detect-only'}
                  description="Prevention"
                  titleColor={summary.prevention_enabled ? 'danger' : 'subdued'}
                />
              }
              description="Prevention remains policy-gated even when correlation and rollback are enabled."
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
                Publish artifact
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
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
            <EuiFlexItem grow={false}>
              <EuiTitle size="m">
                <h3>Policy posture</h3>
              </EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton fill isLoading={isSavingPolicy} onClick={savePolicy}>
                Save policy
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          <EuiCompressedFormRow label="Global mode">
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
              Use `prevent` only when you are ready to enforce kill, block, quarantine, or rollback workflows. Detect mode
              keeps the same telemetry and alerting path without agent-side blocking.
            </p>
          </EuiText>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );

  const renderArtifacts = () => (
    <EuiFlexGroup gutterSize="l" alignItems="flexStart">
      <EuiFlexItem grow={2}>
        <EuiPanel paddingSize="l">
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
            <EuiFlexItem grow={false}>
              <EuiTitle size="m">
                <h3>Artifact registry</h3>
              </EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiBadge color="hollow">{artifacts.length} items</EuiBadge>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          <EuiBasicTable items={artifacts} columns={artifactColumns} />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel paddingSize="l">
          <EuiTitle size="xs">
            <h4>Publish new artifact</h4>
          </EuiTitle>
          <EuiSpacer size="m" />
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
          <EuiSpacer size="m" />
          <EuiButton fill fullWidth isLoading={isSavingArtifact} onClick={saveArtifact}>
            Save artifact
          </EuiButton>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );

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
      <EuiPanel paddingSize="l" className="xdrDefense__headerStrip">
        <EuiFlexGroup alignItems="center" gutterSize="m" responsive>
          <EuiFlexItem grow={false}>
            <EuiBadge color="secondary">Agent-local detection</EuiBadge>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiBadge color="warning">OpenSearch correlation</EuiBadge>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiBadge color="danger">Rollback on confirmation</EuiBadge>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiPanel>

      <EuiSpacer size="l" />

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

      <EuiHorizontalRule margin="xl" />

      <EuiPanel paddingSize="l">
        <EuiTitle size="xs">
          <h4>{i18n.translate('xdrDefense.activityPreview', { defaultMessage: 'API preview' })}</h4>
        </EuiTitle>
        <EuiSpacer size="m" />
        <EuiCodeBlock language="json" overflowHeight={240} isCopyable>
          {JSON.stringify(
            {
              summary,
              manifest,
              correlationRules,
            },
            null,
            2
          )}
        </EuiCodeBlock>
      </EuiPanel>
    </EuiPageTemplate>
  );
};
