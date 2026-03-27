import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';

export interface YaraForgePersistedSyncStatus {
  phase?: 'idle' | 'downloading' | 'validating' | 'rollout' | 'completed' | 'failed';
  release_tag?: string;
  asset_name?: string;
  asset_updated_at?: string;
  last_attempted_at?: string;
  last_completed_at?: string;
  last_successful_sync_at?: string;
  attempted?: number;
  loaded?: number;
  imported?: number;
  unchanged?: number;
  removed?: number;
  load_failures?: number;
  active_rules_queued?: number;
  rollout?: {
    target_agent_commands: number;
    created: number;
    deduplicated: number;
    planned_rules?: number;
    processed_rules?: number;
  };
  last_error?: string;
}

export interface MalwareBazaarPersistedSyncStatus {
  status?: 'idle' | 'processing' | 'completed' | 'failed';
  phase?: 'idle' | 'requesting_export' | 'preparing_download' | 'downloading' | 'importing' | 'completed' | 'failed';
  message?: string;
  api_key_updated_at?: string;
  last_attempted_at?: string;
  last_completed_at?: string;
  last_successful_sync_at?: string;
  last_cursor_seen_at?: string;
  last_query_mode?: string;
  last_upstream_records?: number;
  last_new_hashes?: number;
  last_total_hashes?: number;
  imported?: number;
  unchanged?: number;
  load_failures?: number;
  last_error?: string;
}

export interface MbAutoUpdateSettings {
  enabled: boolean;
  requests_per_day: number;
}

interface UpstreamSyncState {
  version: 1;
  yara_forge: YaraForgePersistedSyncStatus;
  malwarebazaar: MalwareBazaarPersistedSyncStatus;
  mb_auto_update: MbAutoUpdateSettings;
}

const UPSTREAM_SYNC_STATE_FILE = resolvePluginDataPath('sync', 'upstream_sync_state.json');

function defaultState(): UpstreamSyncState {
  return {
    version: 1,
    yara_forge: {},
    malwarebazaar: {},
    mb_auto_update: { enabled: false, requests_per_day: 1000 }
  };
}

function loadState(): UpstreamSyncState {
  const raw = readJsonFile<UpstreamSyncState>(UPSTREAM_SYNC_STATE_FILE, defaultState());
  const rawMb = raw?.mb_auto_update;
  const rawRequestsPerDay = Number(rawMb?.requests_per_day ?? 1000);
  return {
    version: 1,
    yara_forge: raw?.yara_forge && typeof raw.yara_forge === 'object' ? raw.yara_forge : {},
    malwarebazaar: raw?.malwarebazaar && typeof raw.malwarebazaar === 'object' ? raw.malwarebazaar : {},
    mb_auto_update: {
      enabled: Boolean(rawMb?.enabled),
      requests_per_day: Number.isFinite(rawRequestsPerDay)
        ? Math.min(100000, Math.max(1, rawRequestsPerDay))
        : 1000
    }
  };
}

function saveState(state: UpstreamSyncState): void {
  writeJsonFile(UPSTREAM_SYNC_STATE_FILE, state);
}

export function getYaraForgeSyncState(): YaraForgePersistedSyncStatus {
  return loadState().yara_forge;
}

export function updateYaraForgeSyncState(patch: Partial<YaraForgePersistedSyncStatus>): YaraForgePersistedSyncStatus {
  const state = loadState();
  state.yara_forge = {
    ...state.yara_forge,
    ...patch
  };
  saveState(state);
  return state.yara_forge;
}

export function getMalwareBazaarSyncState(): MalwareBazaarPersistedSyncStatus {
  return loadState().malwarebazaar;
}

export function updateMalwareBazaarSyncState(
  patch: Partial<MalwareBazaarPersistedSyncStatus>
): MalwareBazaarPersistedSyncStatus {
  const state = loadState();
  state.malwarebazaar = {
    ...state.malwarebazaar,
    ...patch
  };
  saveState(state);
  return state.malwarebazaar;
}

export function getMbAutoUpdateSettings(): MbAutoUpdateSettings {
  return loadState().mb_auto_update;
}

export function saveMbAutoUpdateSettings(settings: MbAutoUpdateSettings): MbAutoUpdateSettings {
  const validated: MbAutoUpdateSettings = {
    enabled: Boolean(settings.enabled),
    requests_per_day: Math.min(100000, Math.max(1, Math.round(Number(settings.requests_per_day) || 1000)))
  };
  const state = loadState();
  state.mb_auto_update = validated;
  saveState(state);
  return validated;
}