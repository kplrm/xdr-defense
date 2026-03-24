export type PolicyMode = 'detect' | 'prevent';

export interface DefensePolicy {
  mode: PolicyMode;
  capabilities: Record<string, boolean>;
  updatedAt: string;
  version: number;
}

export interface ArtifactEntry {
  id: string;
  type: 'yara' | 'behavioral' | 'hashes' | 'threatintel';
  version: string;
  checksum: string;
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
    'prevention.enabled': false
  },
  updatedAt: new Date().toISOString(),
  version: 1
};

const artifacts = new Map<string, ArtifactEntry>();

let policyState = { ...defaultPolicy };

export function getPolicy(): DefensePolicy {
  return policyState;
}

export function savePolicy(next: Omit<DefensePolicy, 'updatedAt' | 'version'>): DefensePolicy {
  policyState = {
    ...next,
    version: policyState.version + 1,
    updatedAt: new Date().toISOString()
  };
  return policyState;
}

export function upsertArtifact(entry: ArtifactEntry): ArtifactEntry {
  artifacts.set(entry.id, entry);
  return entry;
}

export function listArtifacts(): ArtifactEntry[] {
  return [...artifacts.values()];
}
