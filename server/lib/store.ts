import { ISavedObjectsRepository } from '../../../../src/core/server';

export type PolicyMode = 'detect' | 'prevent';
export type ArtifactType = 'yara' | 'behavioral' | 'hashes' | 'threatintel';
export type FeedType = 'hashes' | 'domain' | 'ip' | 'url';

export const POLICY_SAVED_OBJECT_TYPE = 'xdr-defense-policy';
export const ARTIFACT_SAVED_OBJECT_TYPE = 'xdr-defense-artifact';
export const FEED_SAVED_OBJECT_TYPE = 'xdr-defense-feed';
export const POLICY_DOC_ID = 'global';

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
  updatedAt: string;
  sourceUrl?: string;
  description?: string;
}

export interface ThreatFeedEntry {
  id: string;
  name: string;
  type: FeedType;
  url: string;
  enabled: boolean;
  updatedAt: string;
  lastSyncAt?: string;
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

export async function getPolicy(): Promise<DefensePolicy> {
  const repo = await getRepository();
  try {
    const current = await repo.get<PolicySavedAttributes>(POLICY_SAVED_OBJECT_TYPE, POLICY_DOC_ID);
    return toPolicy(current.attributes);
  } catch (err) {
    if (!isNotFound(err)) {
      throw err;
    }
    const created = await repo.create<PolicySavedAttributes>(
      POLICY_SAVED_OBJECT_TYPE,
      {
        mode: defaultPolicy.mode,
        capabilitiesJSON: JSON.stringify(defaultPolicy.capabilities),
        updatedAt: defaultPolicy.updatedAt,
        version: defaultPolicy.version,
      },
      {
      id: POLICY_DOC_ID,
      overwrite: true,
      }
    );
    return toPolicy(created.attributes);
  }
}

export async function savePolicy(
  next: Omit<DefensePolicy, 'updatedAt' | 'version'>
): Promise<DefensePolicy> {
  const repo = await getRepository();
  const current = await getPolicy();
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
    {
      mode: updated.mode,
      capabilitiesJSON: JSON.stringify(updated.capabilities),
      updatedAt: updated.updatedAt,
      version: updated.version,
    },
    {
      id: POLICY_DOC_ID,
      overwrite: true,
    }
  );
  return updated;
}

export async function upsertArtifact(entry: Omit<ArtifactEntry, 'updatedAt'>): Promise<ArtifactEntry> {
  const repo = await getRepository();
  const now = new Date().toISOString();
  const saved = await repo.create<ArtifactEntry>(
    ARTIFACT_SAVED_OBJECT_TYPE,
    {
      ...entry,
      updatedAt: now,
    },
    {
      id: entry.id,
      overwrite: true,
    }
  );
  return saved.attributes;
}

export async function listArtifacts(): Promise<ArtifactEntry[]> {
  const repo = await getRepository();
  const result = await repo.find<ArtifactEntry>({
    type: ARTIFACT_SAVED_OBJECT_TYPE,
    perPage: 1000,
    page: 1,
  });
  return result.saved_objects.map((obj) => obj.attributes);
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

export async function latestArtifactManifest() {
  const policy = await getPolicy();
  const artifacts = await listArtifacts();
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
