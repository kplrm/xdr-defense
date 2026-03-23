import { ISavedObjectsRepository } from '../../../../src/core/server';

export type PolicyMode = 'detect' | 'prevent';
export type ArtifactType = 'yara' | 'behavioral' | 'hashes' | 'threatintel';
export type FeedType = 'hashes' | 'domain' | 'ip' | 'url';

export const POLICY_SAVED_OBJECT_TYPE = 'xdr-defense-policy';
export const ARTIFACT_SAVED_OBJECT_TYPE = 'xdr-defense-artifact';
export const FEED_SAVED_OBJECT_TYPE = 'xdr-defense-feed';
export const ROLLOUT_SAVED_OBJECT_TYPE = 'xdr-defense-rollout';
export const YARA_ROLLOUT_SAVED_OBJECT_TYPE = 'xdr-defense-yara-rollout';
export const DEFAULT_MANAGER_POLICY_ID = 'default';

export interface DefensePolicy {
  mode: PolicyMode;
  capabilities: Record<string, boolean>;
  updatedAt: string;
  version: number;
}

interface PolicySavedAttributes {
  mode: PolicyMode;
  capabilitiesJSON: string;
  updatedAt: string;
  version: number;
  capabilities?: Record<string, boolean>;
}

export interface ArtifactEntry {
  id: string;
  type: ArtifactType;
  version: string;
  checksum: string;
  enabled: boolean;
  updatedAt: string;
  sourceUrl?: string;
  description?: string;
}

interface ArtifactSavedAttributes {
  id: string;
  type: ArtifactType;
  version: string;
  checksum: string;
  enabled?: boolean;
  enabledByPolicyJSON?: string;
  updatedAt: string;
  sourceUrl?: string;
  description?: string;
}

const defaultBuiltInArtifacts: Array<
  Omit<ArtifactEntry, 'updatedAt' | 'enabled'> & {
    enabled?: boolean;
  }
> = [];

let seedDefaultArtifactsPromise: Promise<void> | null = null;

export interface ThreatFeedEntry {
  id: string;
  name: string;
  type: FeedType;
  url: string;
  enabled: boolean;
  updatedAt: string;
  lastSyncAt?: string;
}

export interface RolloutAgentAck {
  agent_id: string;
  hostname?: string;
  acked_at: string;
}

export interface RolloutSummary {
  policy_id: string;
  posture_version: number;
  updated_at: string;
  target_agent_ids: string[];
  acked_agent_ids: string[];
  pending_agent_ids: string[];
  acked_agents: RolloutAgentAck[];
  retry_requested_at: Record<string, string>;
}

export type YaraRolloutAction = 'sync' | 'activate' | 'deactivate' | 'delete';
export type YaraRolloutAgentState = 'pending' | 'acked' | 'failed';

export interface YaraRolloutAgentStatus {
  agent_id: string;
  hostname?: string;
  state: YaraRolloutAgentState;
  last_action: YaraRolloutAction;
  last_attempted_at: string;
  acked_at?: string;
  failure_reason?: string;
  retry_requested_at?: string;
  retry_in_progress?: boolean;
}

export interface YaraRolloutSummary {
  manager_policy_id: string;
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

interface RolloutSavedAttributes {
  policyId: string;
  postureVersion: number;
  updatedAt: string;
  targetAgentIdsJSON: string;
  ackedAgentsJSON: string;
  retryRequestedAtJSON: string;
}

interface YaraRolloutSavedAttributes {
  managerPolicyId: string;
  action: YaraRolloutAction;
  artifactIdsJSON: string;
  targetAgentIdsJSON: string;
  agentStatusesJSON: string;
  updatedAt: string;
}

const defaultPolicy: DefensePolicy = {
  mode: 'detect',
  capabilities: {
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
  },
  updatedAt: new Date().toISOString(),
  version: 1,
};

export function createDefaultPolicy(): DefensePolicy {
  return {
    ...defaultPolicy,
    capabilities: { ...defaultPolicy.capabilities },
    updatedAt: new Date().toISOString(),
  };
}

let repoPromise: Promise<ISavedObjectsRepository> | undefined;
let resolveRepo: ((repo: ISavedObjectsRepository) => void) | undefined;

export function bindRepository(repo: ISavedObjectsRepository) {
  if (resolveRepo) {
    resolveRepo(repo);
    resolveRepo = undefined;
    return;
  }
  repoPromise = Promise.resolve(repo);
}

async function getRepository(): Promise<ISavedObjectsRepository> {
  if (repoPromise) {
    return repoPromise;
  }
  repoPromise = new Promise<ISavedObjectsRepository>((resolve) => {
    resolveRepo = resolve;
  });
  return repoPromise;
}

function isNotFound(err: any): boolean {
  return Boolean(err?.output?.statusCode === 404 || err?.statusCode === 404);
}

function parseCapabilities(attributes: PolicySavedAttributes): Record<string, boolean> {
  if (attributes.capabilities && typeof attributes.capabilities === 'object') {
    return attributes.capabilities;
  }
  try {
    return JSON.parse(attributes.capabilitiesJSON || '{}');
  } catch {
    return {};
  }
}

function toPolicy(attributes: PolicySavedAttributes): DefensePolicy {
  return {
    mode: attributes.mode,
    capabilities: parseCapabilities(attributes),
    updatedAt: attributes.updatedAt,
    version: attributes.version,
  };
}

function parseStringArrayJSON(value: string | undefined): string[] {
  if (!value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

function parseAckedAgentsJSON(value: string | undefined): RolloutAgentAck[] {
  if (!value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter((item) => item && typeof item === 'object')
      .map((item) => {
        const agentID = typeof item.agent_id === 'string' ? item.agent_id : '';
        const hostname = typeof item.hostname === 'string' ? item.hostname : undefined;
        const ackedAt = typeof item.acked_at === 'string' ? item.acked_at : '';
        return {
          agent_id: agentID,
          hostname,
          acked_at: ackedAt,
        };
      })
      .filter((item) => item.agent_id.length > 0 && item.acked_at.length > 0);
  } catch {
    return [];
  }
}

function parseRetryMapJSON(value: string | undefined): Record<string, string> {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }
    return Object.entries(parsed).reduce<Record<string, string>>((acc, [key, mapValue]) => {
      if (typeof mapValue === 'string') {
        acc[key] = mapValue;
      }
      return acc;
    }, {});
  } catch {
    return {};
  }
}

function toRollout(attributes: RolloutSavedAttributes): RolloutSummary {
  const targetAgentIDs = parseStringArrayJSON(attributes.targetAgentIdsJSON);
  const ackedAgents = parseAckedAgentsJSON(attributes.ackedAgentsJSON);
  const retryRequestedAt = parseRetryMapJSON(attributes.retryRequestedAtJSON);
  const ackedSet = new Set(ackedAgents.map((entry) => entry.agent_id));

  return {
    policy_id: attributes.policyId,
    posture_version: attributes.postureVersion,
    updated_at: attributes.updatedAt,
    target_agent_ids: targetAgentIDs,
    acked_agent_ids: [...ackedSet],
    pending_agent_ids: targetAgentIDs.filter((agentID) => !ackedSet.has(agentID)),
    acked_agents: ackedAgents,
    retry_requested_at: retryRequestedAt,
  };
}

function toRolloutSavedAttributes(rollout: RolloutSummary): RolloutSavedAttributes {
  return {
    policyId: rollout.policy_id,
    postureVersion: rollout.posture_version,
    updatedAt: rollout.updated_at,
    targetAgentIdsJSON: JSON.stringify(rollout.target_agent_ids),
    ackedAgentsJSON: JSON.stringify(rollout.acked_agents),
    retryRequestedAtJSON: JSON.stringify(rollout.retry_requested_at),
  };
}

function rolloutSavedObjectID(policyID: string, postureVersion: number): string {
  return `${policyID}:${postureVersion}`;
}

function yaraRolloutSavedObjectID(managerPolicyID: string): string {
  return `yaraRollout-${managerPolicyID || DEFAULT_MANAGER_POLICY_ID}`;
}

function parseYaraRolloutAgentStatusesJSON(value: string | undefined): YaraRolloutAgentStatus[] {
  if (!value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .filter((entry) => entry && typeof entry === 'object')
      .map((entry) => {
        const agentID = typeof entry.agent_id === 'string' ? entry.agent_id : '';
        const hostname = typeof entry.hostname === 'string' ? entry.hostname : undefined;
        const state =
          entry.state === 'acked' || entry.state === 'failed' || entry.state === 'pending'
            ? entry.state
            : 'pending';
        const lastAction =
          entry.last_action === 'sync' ||
          entry.last_action === 'activate' ||
          entry.last_action === 'deactivate' ||
          entry.last_action === 'delete'
            ? entry.last_action
            : 'sync';
        const lastAttemptedAt =
          typeof entry.last_attempted_at === 'string' ? entry.last_attempted_at : new Date(0).toISOString();
        const ackedAt = typeof entry.acked_at === 'string' ? entry.acked_at : undefined;
        const failureReason = typeof entry.failure_reason === 'string' ? entry.failure_reason : undefined;
        const retryRequestedAt =
          typeof entry.retry_requested_at === 'string' ? entry.retry_requested_at : undefined;
        const retryInProgress = typeof entry.retry_in_progress === 'boolean' ? entry.retry_in_progress : undefined;

        return {
          agent_id: agentID,
          hostname,
          state,
          last_action: lastAction,
          last_attempted_at: lastAttemptedAt,
          acked_at: ackedAt,
          failure_reason: failureReason,
          retry_requested_at: retryRequestedAt,
          retry_in_progress: retryInProgress,
        } as YaraRolloutAgentStatus;
      })
      .filter((entry) => entry.agent_id.length > 0);
  } catch {
    return [];
  }
}

function defaultYaraStaleAfterSeconds(): number {
  const configured = Number(process.env.XDR_DEFENSE_YARA_ROLLOUT_STALE_AFTER_SECONDS || '900');
  if (!Number.isFinite(configured) || configured < 60) {
    return 900;
  }
  return Math.floor(configured);
}

function isStalePendingAgentStatus(
  status: YaraRolloutAgentStatus,
  staleAfterSeconds: number,
  nowMs: number
): boolean {
  if (status.state !== 'pending') {
    return false;
  }

  const candidateTimestamp = status.retry_requested_at || status.last_attempted_at;
  const parsed = Date.parse(candidateTimestamp);
  if (Number.isNaN(parsed)) {
    return true;
  }

  return nowMs - parsed >= staleAfterSeconds * 1000;
}

function toYaraRollout(
  attributes: YaraRolloutSavedAttributes,
  staleAfterSeconds = defaultYaraStaleAfterSeconds()
): YaraRolloutSummary {
  const targetAgentIDs = parseStringArrayJSON(attributes.targetAgentIdsJSON);
  const artifactIDs = parseStringArrayJSON(attributes.artifactIdsJSON);
  const savedStatuses = parseYaraRolloutAgentStatusesJSON(attributes.agentStatusesJSON);
  const byAgentID = savedStatuses.reduce<Record<string, YaraRolloutAgentStatus>>((acc, status) => {
    acc[status.agent_id] = status;
    return acc;
  }, {});

  const normalizedStatuses = targetAgentIDs.map((agentID) => {
    const existing = byAgentID[agentID];
    if (existing) {
      return existing;
    }
    return {
      agent_id: agentID,
      state: 'pending' as const,
      last_action: attributes.action,
      last_attempted_at: attributes.updatedAt,
    };
  });

  const nowMs = Date.now();
  const pendingAgentIDs: string[] = [];
  const ackedAgentIDs: string[] = [];
  const failedAgentIDs: string[] = [];
  const stalePendingAgentIDs: string[] = [];

  normalizedStatuses.forEach((status) => {
    if (status.state === 'acked') {
      ackedAgentIDs.push(status.agent_id);
      return;
    }

    if (status.state === 'failed') {
      failedAgentIDs.push(status.agent_id);
      return;
    }

    pendingAgentIDs.push(status.agent_id);
    if (isStalePendingAgentStatus(status, staleAfterSeconds, nowMs)) {
      stalePendingAgentIDs.push(status.agent_id);
    }
  });

  return {
    manager_policy_id: attributes.managerPolicyId,
    action: attributes.action,
    artifact_ids: artifactIDs,
    updated_at: attributes.updatedAt,
    target_agent_ids: targetAgentIDs,
    pending_agent_ids: pendingAgentIDs,
    acked_agent_ids: ackedAgentIDs,
    failed_agent_ids: failedAgentIDs,
    stale_pending_agent_ids: stalePendingAgentIDs,
    stale_after_seconds: staleAfterSeconds,
    agents: normalizedStatuses,
  };
}

function toYaraRolloutSavedAttributes(summary: YaraRolloutSummary): YaraRolloutSavedAttributes {
  return {
    managerPolicyId: summary.manager_policy_id,
    action: summary.action,
    artifactIdsJSON: JSON.stringify(summary.artifact_ids),
    targetAgentIdsJSON: JSON.stringify(summary.target_agent_ids),
    agentStatusesJSON: JSON.stringify(summary.agents),
    updatedAt: summary.updated_at,
  };
}

export async function getPolicy(): Promise<DefensePolicy> {
  return getPolicyOverlay(DEFAULT_MANAGER_POLICY_ID);
}

function toPolicySavedAttributes(policy: DefensePolicy): PolicySavedAttributes {
  return {
    mode: policy.mode,
    capabilitiesJSON: JSON.stringify(policy.capabilities),
    updatedAt: policy.updatedAt,
    version: policy.version,
  };
}

export async function listPolicyOverlays(): Promise<Array<{ managerPolicyID: string; overlay: DefensePolicy }>> {
  const repo = await getRepository();
  const result = await repo.find<PolicySavedAttributes>({
    type: POLICY_SAVED_OBJECT_TYPE,
    perPage: 1000,
    page: 1,
  });

  return result.saved_objects
    .map((obj) => ({ managerPolicyID: obj.id, overlay: toPolicy(obj.attributes) }))
    .sort((a, b) => a.managerPolicyID.localeCompare(b.managerPolicyID));
}

export async function getPolicyOverlay(managerPolicyID: string): Promise<DefensePolicy> {
  const repo = await getRepository();
  const normalizedPolicyID = managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
  try {
    const current = await repo.get<PolicySavedAttributes>(POLICY_SAVED_OBJECT_TYPE, normalizedPolicyID);
    return toPolicy(current.attributes);
  } catch (err) {
    if (!isNotFound(err)) {
      throw err;
    }

    const nextDefault = createDefaultPolicy();
    const created = await repo.create<PolicySavedAttributes>(
      POLICY_SAVED_OBJECT_TYPE,
      toPolicySavedAttributes(nextDefault),
      {
        id: normalizedPolicyID,
        overwrite: true,
      }
    );
    return toPolicy(created.attributes);
  }
}

export async function getEffectivePolicy(policyID?: string): Promise<DefensePolicy> {
  return getPolicyOverlay(policyID || DEFAULT_MANAGER_POLICY_ID);
}

export async function savePolicy(
  next: Omit<DefensePolicy, 'updatedAt' | 'version'>
): Promise<DefensePolicy> {
  return savePolicyOverlay(DEFAULT_MANAGER_POLICY_ID, next);
}

export async function savePolicyOverlay(
  managerPolicyID: string,
  next: Omit<DefensePolicy, 'updatedAt' | 'version'>
): Promise<DefensePolicy> {
  const repo = await getRepository();
  const normalizedPolicyID = managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
  const current = await getPolicyOverlay(normalizedPolicyID);
  const updated: DefensePolicy = {
    ...next,
    capabilities: {
      ...current.capabilities,
      ...next.capabilities,
    },
    version: current.version + 1,
    updatedAt: new Date().toISOString(),
  };
  await repo.create<PolicySavedAttributes>(
    POLICY_SAVED_OBJECT_TYPE,
    toPolicySavedAttributes(updated),
    {
      id: normalizedPolicyID,
      overwrite: true,
    }
  );
  return updated;
}

function toArtifact(attributes: ArtifactSavedAttributes): ArtifactEntry {
  return {
    ...attributes,
    enabled: attributes.enabled !== false,
  };
}

function parseArtifactPolicyOverrides(
  attributes: ArtifactSavedAttributes
): Record<string, boolean> {
  if (!attributes.enabledByPolicyJSON) {
    return {};
  }
  try {
    const parsed = JSON.parse(attributes.enabledByPolicyJSON);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }

    return Object.entries(parsed).reduce<Record<string, boolean>>((acc, [policyID, value]) => {
      if (typeof value === 'boolean') {
        acc[policyID] = value;
      }
      return acc;
    }, {});
  } catch {
    return {};
  }
}

function resolveArtifactEnabled(attributes: ArtifactSavedAttributes, policyID?: string): boolean {
  if (!policyID) {
    return attributes.enabled !== false;
  }

  const overrides = parseArtifactPolicyOverrides(attributes);
  if (Object.prototype.hasOwnProperty.call(overrides, policyID)) {
    return overrides[policyID];
  }

  return attributes.enabled !== false;
}

function toArtifactForPolicy(attributes: ArtifactSavedAttributes, policyID?: string): ArtifactEntry {
  const artifact = toArtifact(attributes);
  return {
    ...artifact,
    enabled: resolveArtifactEnabled(attributes, policyID),
  };
}

export async function ensureDefaultArtifactsSeeded(): Promise<void> {
  if (seedDefaultArtifactsPromise) {
    return seedDefaultArtifactsPromise;
  }

  seedDefaultArtifactsPromise = (async () => {
    const repo = await getRepository();
    await Promise.all(
      defaultBuiltInArtifacts.map(async (artifact) => {
        try {
          const current = await repo.get<ArtifactSavedAttributes>(ARTIFACT_SAVED_OBJECT_TYPE, artifact.id);
          const attributes = current.attributes;
          const needsRefresh =
            attributes.type !== artifact.type ||
            attributes.version !== artifact.version ||
            attributes.checksum !== artifact.checksum ||
            attributes.sourceUrl !== artifact.sourceUrl ||
            attributes.description !== artifact.description;

          if (!needsRefresh) {
            return;
          }

          await repo.create<ArtifactSavedAttributes>(
            ARTIFACT_SAVED_OBJECT_TYPE,
            {
              ...attributes,
              type: artifact.type,
              version: artifact.version,
              checksum: artifact.checksum,
              sourceUrl: artifact.sourceUrl,
              description: artifact.description,
              updatedAt: new Date().toISOString(),
            },
            {
              id: artifact.id,
              overwrite: true,
            }
          );
        } catch (err) {
          if (!isNotFound(err)) {
            throw err;
          }
          await upsertArtifact(artifact);
        }
      })
    );
  })();

  try {
    await seedDefaultArtifactsPromise;
  } finally {
    seedDefaultArtifactsPromise = null;
  }
}

export async function upsertArtifact(
  entry: Omit<ArtifactEntry, 'updatedAt' | 'enabled'> & { enabled?: boolean }
): Promise<ArtifactEntry> {
  const repo = await getRepository();
  const now = new Date().toISOString();
  let existingPolicyOverridesJSON: string | undefined;
  try {
    const current = await repo.get<ArtifactSavedAttributes>(ARTIFACT_SAVED_OBJECT_TYPE, entry.id);
    existingPolicyOverridesJSON = current.attributes.enabledByPolicyJSON;
  } catch (err) {
    if (!isNotFound(err)) {
      throw err;
    }
  }

  const saved = await repo.create<ArtifactSavedAttributes>(
    ARTIFACT_SAVED_OBJECT_TYPE,
    {
      ...entry,
      enabled: entry.enabled !== false,
      enabledByPolicyJSON: existingPolicyOverridesJSON,
      updatedAt: now,
    },
    {
      id: entry.id,
      overwrite: true,
    }
  );
  return toArtifact(saved.attributes);
}

export async function setArtifactEnabled(
  artifactID: string,
  enabled: boolean,
  policyID?: string
): Promise<ArtifactEntry> {
  const repo = await getRepository();
  const current = await repo.get<ArtifactSavedAttributes>(ARTIFACT_SAVED_OBJECT_TYPE, artifactID);
  const policyOverrides = parseArtifactPolicyOverrides(current.attributes);

  if (policyID) {
    policyOverrides[policyID] = enabled;
  }

  const updated: ArtifactSavedAttributes = {
    ...current.attributes,
    enabled: policyID ? current.attributes.enabled !== false : enabled,
    enabledByPolicyJSON: JSON.stringify(policyOverrides),
    updatedAt: new Date().toISOString(),
  };
  const saved = await repo.create<ArtifactSavedAttributes>(ARTIFACT_SAVED_OBJECT_TYPE, updated, {
    id: artifactID,
    overwrite: true,
  });
  return toArtifactForPolicy(saved.attributes, policyID);
}

export async function deleteArtifact(artifactID: string): Promise<boolean> {
  const repo = await getRepository();
  try {
    await repo.delete(ARTIFACT_SAVED_OBJECT_TYPE, artifactID);
    return true;
  } catch (err) {
    if (isNotFound(err)) {
      return false;
    }
    throw err;
  }
}

export async function listArtifacts(policyID?: string): Promise<ArtifactEntry[]> {
  await ensureDefaultArtifactsSeeded();
  const repo = await getRepository();
  const result = await repo.find<ArtifactSavedAttributes>({
    type: ARTIFACT_SAVED_OBJECT_TYPE,
    perPage: 10000,
    page: 1,
  });
  return result.saved_objects.map((obj) => toArtifactForPolicy(obj.attributes, policyID));
}

export async function upsertThreatFeed(
  entry: Omit<ThreatFeedEntry, 'updatedAt' | 'lastSyncAt'>
): Promise<ThreatFeedEntry> {
  const repo = await getRepository();
  const saved = await repo.create<ThreatFeedEntry>(
    FEED_SAVED_OBJECT_TYPE,
    {
      ...entry,
      updatedAt: new Date().toISOString(),
    },
    {
      id: entry.id,
      overwrite: true,
    }
  );
  return saved.attributes;
}

export async function listThreatFeeds(): Promise<ThreatFeedEntry[]> {
  const repo = await getRepository();
  const result = await repo.find<ThreatFeedEntry>({
    type: FEED_SAVED_OBJECT_TYPE,
    perPage: 1000,
    page: 1,
  });
  return result.saved_objects.map((obj) => obj.attributes);
}

export async function markThreatFeedSynced(feedID: string): Promise<ThreatFeedEntry> {
  const repo = await getRepository();
  const current = await repo.get<ThreatFeedEntry>(FEED_SAVED_OBJECT_TYPE, feedID);
  const updated: ThreatFeedEntry = {
    ...current.attributes,
    updatedAt: new Date().toISOString(),
    lastSyncAt: new Date().toISOString(),
  };
  const saved = await repo.create<ThreatFeedEntry>(FEED_SAVED_OBJECT_TYPE, updated, {
    id: feedID,
    overwrite: true,
  });
  return saved.attributes;
}

export async function latestArtifactManifest(policyID?: string) {
  const policy = await getEffectivePolicy(policyID);
  const artifacts = (await listArtifacts(policyID)).filter((artifact) => artifact.enabled);
  return {
    manifest_version: 1,
    policy_version: policy.version,
    activation_timestamp: new Date().toISOString(),
    artifacts: artifacts.map((artifact) => ({
      type: artifact.type,
      id: artifact.id,
      version: artifact.version,
      checksum: artifact.checksum,
      updated_at: artifact.updatedAt,
      source_url: artifact.sourceUrl,
      target_path:
        artifact.type === 'yara'
          ? '/etc/xdr-agent/rules/malware/yara'
          : artifact.type === 'behavioral'
            ? '/etc/xdr-agent/rules/behavioral'
            : artifact.type === 'hashes'
              ? '/etc/xdr-agent/rules/malware'
              : '/etc/xdr-agent/rules/threat-intel',
    })),
  };
}

export async function savePolicyRollout(
  policyID: string,
  postureVersion: number,
  targetAgentIDs: string[]
): Promise<RolloutSummary> {
  const repo = await getRepository();
  const normalizedPolicyID = policyID || DEFAULT_MANAGER_POLICY_ID;
  const uniqueTargets = [...new Set(targetAgentIDs.filter((agentID) => agentID.length > 0))];
  const now = new Date().toISOString();

  const rollout: RolloutSummary = {
    policy_id: normalizedPolicyID,
    posture_version: postureVersion,
    updated_at: now,
    target_agent_ids: uniqueTargets,
    acked_agent_ids: [],
    pending_agent_ids: uniqueTargets,
    acked_agents: [],
    retry_requested_at: {},
  };

  const saved = await repo.create<RolloutSavedAttributes>(
    ROLLOUT_SAVED_OBJECT_TYPE,
    toRolloutSavedAttributes(rollout),
    {
      id: rolloutSavedObjectID(normalizedPolicyID, postureVersion),
      overwrite: true,
    }
  );

  return toRollout(saved.attributes);
}

export async function getPolicyRollout(
  policyID: string,
  postureVersion: number
): Promise<RolloutSummary | null> {
  const repo = await getRepository();
  try {
    const saved = await repo.get<RolloutSavedAttributes>(
      ROLLOUT_SAVED_OBJECT_TYPE,
      rolloutSavedObjectID(policyID || DEFAULT_MANAGER_POLICY_ID, postureVersion)
    );
    return toRollout(saved.attributes);
  } catch (err) {
    if (isNotFound(err)) {
      return null;
    }
    throw err;
  }
}

export async function getLatestPolicyRollout(policyID: string): Promise<RolloutSummary | null> {
  const normalizedPolicyID = policyID || DEFAULT_MANAGER_POLICY_ID;
  const repo = await getRepository();
  const result = await repo.find<RolloutSavedAttributes>({
    type: ROLLOUT_SAVED_OBJECT_TYPE,
    perPage: 1000,
    page: 1,
    sortField: 'updatedAt',
    sortOrder: 'desc',
  });

  const matching = result.saved_objects
    .map((saved) => toRollout(saved.attributes))
    .filter((rollout) => rollout.policy_id === normalizedPolicyID)
    .sort((a, b) => b.posture_version - a.posture_version);

  return matching[0] ?? null;
}

export async function acknowledgePolicyRolloutAgent(params: {
  policyID: string;
  postureVersion: number;
  agentID: string;
  hostname?: string;
}): Promise<RolloutSummary> {
  const current =
    (await getPolicyRollout(params.policyID, params.postureVersion)) ??
    (await savePolicyRollout(params.policyID, params.postureVersion, [params.agentID]));

  const now = new Date().toISOString();
  const ackedAgents = current.acked_agents.filter((entry) => entry.agent_id !== params.agentID);
  ackedAgents.push({
    agent_id: params.agentID,
    hostname: params.hostname,
    acked_at: now,
  });

  const mergedTargets = current.target_agent_ids.includes(params.agentID)
    ? current.target_agent_ids
    : [...current.target_agent_ids, params.agentID];

  const updated: RolloutSummary = {
    ...current,
    updated_at: now,
    target_agent_ids: mergedTargets,
    acked_agents: ackedAgents,
    acked_agent_ids: [...new Set(ackedAgents.map((entry) => entry.agent_id))],
    pending_agent_ids: mergedTargets.filter(
      (agentID) => !ackedAgents.some((entry) => entry.agent_id === agentID)
    ),
  };

  const repo = await getRepository();
  const saved = await repo.create<RolloutSavedAttributes>(
    ROLLOUT_SAVED_OBJECT_TYPE,
    toRolloutSavedAttributes(updated),
    {
      id: rolloutSavedObjectID(updated.policy_id, updated.posture_version),
      overwrite: true,
    }
  );
  return toRollout(saved.attributes);
}

export async function markPolicyRolloutRetry(params: {
  policyID: string;
  agentIDs?: string[];
}): Promise<RolloutSummary | null> {
  const latest = await getLatestPolicyRollout(params.policyID);
  if (!latest) {
    return null;
  }

  const now = new Date().toISOString();
  const pendingSet = new Set(latest.pending_agent_ids);
  const candidateAgentIDs = params.agentIDs?.length
    ? params.agentIDs.filter((agentID) => pendingSet.has(agentID))
    : latest.pending_agent_ids;

  const retryRequestedAt = { ...latest.retry_requested_at };
  candidateAgentIDs.forEach((agentID) => {
    retryRequestedAt[agentID] = now;
  });

  const updated: RolloutSummary = {
    ...latest,
    updated_at: now,
    retry_requested_at: retryRequestedAt,
  };

  const repo = await getRepository();
  const saved = await repo.create<RolloutSavedAttributes>(
    ROLLOUT_SAVED_OBJECT_TYPE,
    toRolloutSavedAttributes(updated),
    {
      id: rolloutSavedObjectID(updated.policy_id, updated.posture_version),
      overwrite: true,
    }
  );

  return toRollout(saved.attributes);
}

export async function saveYaraRollout(params: {
  managerPolicyID: string;
  action: YaraRolloutAction;
  artifactIDs: string[];
  targetAgentIDs: string[];
}): Promise<YaraRolloutSummary> {
  const repo = await getRepository();
  const normalizedPolicyID = params.managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
  const now = new Date().toISOString();

  const uniqueTargetAgentIDs = [...new Set(params.targetAgentIDs.filter((agentID) => agentID.length > 0))];
  const uniqueArtifactIDs = [...new Set(params.artifactIDs.filter((artifactID) => artifactID.length > 0))];

  const agents: YaraRolloutAgentStatus[] = uniqueTargetAgentIDs.map((agentID) => ({
    agent_id: agentID,
    state: 'pending',
    last_action: params.action,
    last_attempted_at: now,
  }));

  const nextSummary: YaraRolloutSummary = {
    manager_policy_id: normalizedPolicyID,
    action: params.action,
    artifact_ids: uniqueArtifactIDs,
    updated_at: now,
    target_agent_ids: uniqueTargetAgentIDs,
    pending_agent_ids: uniqueTargetAgentIDs,
    acked_agent_ids: [],
    failed_agent_ids: [],
    stale_pending_agent_ids: [],
    stale_after_seconds: defaultYaraStaleAfterSeconds(),
    agents,
  };

  const saved = await repo.create<YaraRolloutSavedAttributes>(
    YARA_ROLLOUT_SAVED_OBJECT_TYPE,
    toYaraRolloutSavedAttributes(nextSummary),
    {
      id: yaraRolloutSavedObjectID(normalizedPolicyID),
      overwrite: true,
    }
  );

  return toYaraRollout(saved.attributes);
}

export async function getLatestYaraRollout(
  managerPolicyID: string,
  staleAfterSeconds = defaultYaraStaleAfterSeconds()
): Promise<YaraRolloutSummary | null> {
  const normalizedPolicyID = managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
  const repo = await getRepository();
  try {
    const saved = await repo.get<YaraRolloutSavedAttributes>(
      YARA_ROLLOUT_SAVED_OBJECT_TYPE,
      yaraRolloutSavedObjectID(normalizedPolicyID)
    );
    return toYaraRollout(saved.attributes, staleAfterSeconds);
  } catch (err) {
    if (isNotFound(err)) {
      return null;
    }
    throw err;
  }
}

export async function acknowledgeYaraRolloutAgent(params: {
  managerPolicyID: string;
  agentID: string;
  hostname?: string;
  state: Exclude<YaraRolloutAgentState, 'pending'>;
  failureReason?: string;
  action?: YaraRolloutAction;
}): Promise<YaraRolloutSummary | null> {
  const repo = await getRepository();
  const normalizedPolicyID = params.managerPolicyID || DEFAULT_MANAGER_POLICY_ID;
  const objectID = yaraRolloutSavedObjectID(normalizedPolicyID);

  try {
    const currentSaved = await repo.get<YaraRolloutSavedAttributes>(YARA_ROLLOUT_SAVED_OBJECT_TYPE, objectID);
    const current = toYaraRollout(currentSaved.attributes);
    const now = new Date().toISOString();

    const mergedTargetIDs = current.target_agent_ids.includes(params.agentID)
      ? current.target_agent_ids
      : [...current.target_agent_ids, params.agentID];

    const nextAgents = mergedTargetIDs.map((agentID) => {
      const existing = current.agents.find((candidate) => candidate.agent_id === agentID);
      if (agentID !== params.agentID) {
        return (
          existing || {
            agent_id: agentID,
            state: 'pending' as const,
            last_action: current.action,
            last_attempted_at: now,
          }
        );
      }

      const baseAction = params.action || current.action;
      return {
        agent_id: agentID,
        hostname: params.hostname || existing?.hostname,
        state: params.state,
        last_action: baseAction,
        last_attempted_at: now,
        acked_at: params.state === 'acked' ? now : undefined,
        failure_reason: params.state === 'failed' ? params.failureReason || 'Agent reported rollout failure' : undefined,
        retry_requested_at: existing?.retry_requested_at,
        retry_in_progress: false,
      };
    });

    const updated: YaraRolloutSummary = {
      ...current,
      updated_at: now,
      target_agent_ids: mergedTargetIDs,
      action: params.action || current.action,
      agents: nextAgents,
      pending_agent_ids: [],
      acked_agent_ids: [],
      failed_agent_ids: [],
      stale_pending_agent_ids: [],
    };

    const saved = await repo.create<YaraRolloutSavedAttributes>(
      YARA_ROLLOUT_SAVED_OBJECT_TYPE,
      toYaraRolloutSavedAttributes(updated),
      {
        id: objectID,
        overwrite: true,
      }
    );

    return toYaraRollout(saved.attributes);
  } catch (err) {
    if (isNotFound(err)) {
      return null;
    }
    throw err;
  }
}

export async function markYaraRolloutRetry(params: {
  managerPolicyID: string;
  agentIDs?: string[];
}): Promise<YaraRolloutSummary | null> {
  const latest = await getLatestYaraRollout(params.managerPolicyID);
  if (!latest) {
    return null;
  }

  const now = new Date().toISOString();
  const targetSet = params.agentIDs?.length
    ? new Set(params.agentIDs)
    : new Set([...latest.pending_agent_ids, ...latest.failed_agent_ids, ...latest.stale_pending_agent_ids]);

  const nextAgents = latest.agents.map((agent) => {
    if (!targetSet.has(agent.agent_id)) {
      return agent;
    }

    return {
      ...agent,
      state: 'pending' as const,
      last_attempted_at: now,
      retry_requested_at: now,
      retry_in_progress: true,
    };
  });

  const updated: YaraRolloutSummary = {
    ...latest,
    updated_at: now,
    agents: nextAgents,
    pending_agent_ids: [],
    acked_agent_ids: [],
    failed_agent_ids: [],
    stale_pending_agent_ids: [],
  };

  const repo = await getRepository();
  const saved = await repo.create<YaraRolloutSavedAttributes>(
    YARA_ROLLOUT_SAVED_OBJECT_TYPE,
    toYaraRolloutSavedAttributes(updated),
    {
      id: yaraRolloutSavedObjectID(updated.manager_policy_id),
      overwrite: true,
    }
  );

  return toYaraRollout(saved.attributes);
}
