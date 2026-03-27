import { type HashIndexDocument, isEligibleHashBundleRule } from './hashes_index';
import { readJsonFile, resolvePluginDataPath, writeJsonFile } from './persistent_state';

export interface ImmediateCustomHashOverlayState {
  version: 1;
  bundle_version: number;
  generated_at: string;
  pending_doc_ids: string[];
}

interface ImmediateCustomHashOverlayMutation {
  id: string;
  doc?: HashIndexDocument | null;
  forceVersionBump?: boolean;
}

const IMMEDIATE_CUSTOM_HASH_OVERLAY_STATE_FILE = resolvePluginDataPath(
  'hashes',
  'immediate_custom_overlay_state.json'
);

let stateCache: ImmediateCustomHashOverlayState | null = null;

function isoNow(): string {
  return new Date().toISOString();
}

function defaultState(): ImmediateCustomHashOverlayState {
  return {
    version: 1,
    bundle_version: 0,
    generated_at: '1970-01-01T00:00:00.000Z',
    pending_doc_ids: []
  };
}

function normalizePendingDocIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }

  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const entry of raw) {
    const id = String(entry ?? '').trim();
    if (!id || seen.has(id)) {
      continue;
    }
    seen.add(id);
    normalized.push(id);
  }

  normalized.sort((left, right) => left.localeCompare(right));
  return normalized;
}

function loadState(): ImmediateCustomHashOverlayState {
  if (stateCache) {
    return stateCache;
  }

  const raw = readJsonFile<ImmediateCustomHashOverlayState>(IMMEDIATE_CUSTOM_HASH_OVERLAY_STATE_FILE, defaultState());
  stateCache = {
    version: 1,
    bundle_version: Math.max(0, Math.floor(Number(raw?.bundle_version ?? 0) || 0)),
    generated_at:
      typeof raw?.generated_at === 'string' && raw.generated_at.trim().length > 0
        ? raw.generated_at
        : '1970-01-01T00:00:00.000Z',
    pending_doc_ids: normalizePendingDocIds(raw?.pending_doc_ids)
  };

  return stateCache;
}

function saveState(state: ImmediateCustomHashOverlayState): ImmediateCustomHashOverlayState {
  stateCache = state;
  writeJsonFile(IMMEDIATE_CUSTOM_HASH_OVERLAY_STATE_FILE, state);
  return state;
}

export function getImmediateCustomHashOverlayState(): ImmediateCustomHashOverlayState {
  const state = loadState();
  return {
    ...state,
    pending_doc_ids: [...state.pending_doc_ids]
  };
}

export function isEligibleImmediateCustomHashOverlayDocument(doc?: HashIndexDocument | null): boolean {
  if (!doc) {
    return false;
  }

  if (doc.source !== 'custom') {
    return false;
  }

  if (!String(doc.sha256_hash ?? '').trim()) {
    return false;
  }

  return isEligibleHashBundleRule(doc);
}

export function reconcileImmediateCustomHashOverlayState(
  mutations: ImmediateCustomHashOverlayMutation[]
): ImmediateCustomHashOverlayState {
  if (mutations.length === 0) {
    return getImmediateCustomHashOverlayState();
  }

  const state = loadState();
  const pending = new Set<string>(state.pending_doc_ids);
  let changed = false;

  for (const mutation of mutations) {
    const id = String(mutation.id ?? '').trim();
    if (!id) {
      continue;
    }

    if (isEligibleImmediateCustomHashOverlayDocument(mutation.doc)) {
      if (!pending.has(id)) {
        pending.add(id);
        changed = true;
      } else if (mutation.forceVersionBump) {
        changed = true;
      }
      continue;
    }

    if (pending.delete(id)) {
      changed = true;
    }
  }

  const nextPendingDocIds = [...pending].sort((left, right) => left.localeCompare(right));
  if (!changed && nextPendingDocIds.length === state.pending_doc_ids.length) {
    return getImmediateCustomHashOverlayState();
  }

  return saveState({
    version: 1,
    bundle_version: state.bundle_version + (changed ? 1 : 0),
    generated_at: changed ? isoNow() : state.generated_at,
    pending_doc_ids: nextPendingDocIds
  });
}

export function clearImmediateCustomHashOverlayState(): ImmediateCustomHashOverlayState {
  const state = loadState();
  if (state.pending_doc_ids.length === 0) {
    return getImmediateCustomHashOverlayState();
  }

  return saveState({
    version: 1,
    bundle_version: state.bundle_version + 1,
    generated_at: isoNow(),
    pending_doc_ids: []
  });
}

export function bumpImmediateCustomHashOverlayBundleVersion(): ImmediateCustomHashOverlayState {
  const state = loadState();
  return saveState({
    version: 1,
    bundle_version: state.bundle_version + 1,
    generated_at: isoNow(),
    pending_doc_ids: [...state.pending_doc_ids]
  });
}