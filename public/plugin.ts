import { PLUGIN_CATEGORY, PLUGIN_ID, PLUGIN_NAME } from '../common';

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

class XdrDefenseUi {
  private readonly host: HTMLElement;

  private readonly http: {
    get: (path: string) => Promise<unknown>;
    post: (path: string, options: { body: string }) => Promise<unknown>;
    put: (path: string, options: { body: string }) => Promise<unknown>;
    delete: (path: string) => Promise<unknown>;
  };

  private activeTab = 'detection-content';

  private yaraRules: ManagedRule[] = [];

  private hashRules: ManagedRule[] = [];

  private behavioralRules: ManagedRule[] = [];

  private bundleMetadata: BundleMetadata | null = null;

  private rolloutStatus: RolloutStatusResponse | null = null;

  private drawerOpen: 'none' | 'yara' | 'hashes' | 'behavioral' = 'none';

  private bannerEl: HTMLElement | null = null;

  constructor(host: HTMLElement, http: XdrDefenseUi['http']) {
    this.host = host;
    this.http = http;
  }

  public async mount(): Promise<void> {
    this.host.innerHTML = '';
    this.host.appendChild(this.createStyles());
    this.host.appendChild(this.renderScaffold());
    await this.refreshAll();
    this.renderTab();
  }

  private async refreshAll(): Promise<void> {
    await Promise.all([
      this.refreshYaraRules(),
      this.refreshHashRules(),
      this.refreshBehavioralRules(),
      this.refreshBundleMetadata(),
      this.refreshRolloutStatus()
    ]);
  }

  private createStyles(): HTMLStyleElement {
    const style = document.createElement('style');
    style.textContent = `
      :root {
        --xdr-bg: #f5f7fa;
        --xdr-surface: #ffffff;
        --xdr-border: #d3dae6;
        --xdr-border-soft: #e5e9f0;
        --xdr-text: #1f2933;
        --xdr-muted: #68778d;
        --xdr-primary: #007d8a;
        --xdr-primary-strong: #005f69;
      }
      .xdr-defense-app {
        font-family: 'Open Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        padding: 22px;
        color: var(--xdr-text);
        background: linear-gradient(180deg, #f7f9fc 0%, #f3f6fa 100%);
        border: 1px solid var(--xdr-border-soft);
        border-radius: 8px;
        max-width: 1600px;
      }
      .xdr-defense-app h1 {
        margin: 0 0 6px;
        font-size: 32px;
        line-height: 1.12;
        letter-spacing: -0.02em;
        font-weight: 600;
      }
      .xdr-defense-subtitle {
        margin: 0 0 14px;
        color: var(--xdr-muted);
        font-size: 15px;
      }
      .xdr-defense-banner {
        margin-bottom: 14px;
        padding: 10px 12px;
        border-radius: 6px;
        display: none;
        white-space: pre-wrap;
        border-left: 3px solid transparent;
      }
      .xdr-defense-banner.error { display: block; background: #fcefee; color: #8f1d18; border: 1px solid #f2c3bf; border-left-color: #d36058; }
      .xdr-defense-banner.success { display: block; background: #ecf8f2; color: #0f5132; border: 1px solid #b7e1c8; border-left-color: #2f855a; }
      .xdr-defense-tabs {
        display: flex;
        gap: 6px;
        border-bottom: 1px solid var(--xdr-border);
        margin-bottom: 16px;
        flex-wrap: wrap;
      }
      .xdr-defense-tab {
        background: #f2f5f8;
        border: 1px solid var(--xdr-border);
        border-bottom: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        padding: 8px 14px;
        font-weight: 500;
        color: #344054;
        cursor: pointer;
      }
      .xdr-defense-tab.active {
        background: var(--xdr-surface);
        color: #0f172a;
        font-weight: 600;
      }
      .xdr-defense-panel {
        border: 1px solid var(--xdr-border);
        border-radius: 8px;
        padding: 18px;
        background: var(--xdr-surface);
        box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
      }
      .xdr-defense-grid {
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        margin-bottom: 16px;
      }
      .xdr-defense-card {
        border: 1px solid var(--xdr-border-soft);
        border-radius: 8px;
        padding: 12px;
        background: linear-gradient(180deg, #ffffff 0%, #f8fbfd 100%);
      }
      .xdr-defense-muted { color: var(--xdr-muted); }
      .xdr-defense-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
      .xdr-defense-table {
        width: 100%;
        border-collapse: collapse;
        border: 1px solid var(--xdr-border-soft);
        border-radius: 8px;
        overflow: hidden;
      }
      .xdr-defense-table th,
      .xdr-defense-table td {
        border-bottom: 1px solid var(--xdr-border-soft);
        text-align: left;
        padding: 10px 9px;
        vertical-align: top;
      }
      .xdr-defense-table tr:nth-child(even) td { background: #fbfcfe; }
      .xdr-defense-table th {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--xdr-muted);
        background: #f6f8fb;
      }
      .xdr-defense-badge {
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        padding: 3px 9px;
        display: inline-block;
      }
      .xdr-defense-badge.valid { background: #e8f8ef; color: #116149; }
      .xdr-defense-badge.invalid { background: #fef0ef; color: #8f1d18; }
      .xdr-defense-badge.pending { background: #fff7e6; color: #7a4f01; }
      .xdr-defense-badge.acknowledged { background: #e8f8ef; color: #116149; }
      .xdr-defense-badge.failed { background: #fef0ef; color: #8f1d18; }
      .xdr-defense-input,
      .xdr-defense-textarea,
      .xdr-defense-select {
        border: 1px solid #c6d0dc;
        border-radius: 6px;
        padding: 9px 10px;
        width: 100%;
        box-sizing: border-box;
      }
      .xdr-defense-input:focus,
      .xdr-defense-textarea:focus,
      .xdr-defense-select:focus {
        outline: 2px solid #b7dde2;
        border-color: var(--xdr-primary);
      }
      .xdr-defense-textarea { min-height: 120px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      .xdr-defense-btn {
        border: 1px solid var(--xdr-primary);
        background: var(--xdr-primary);
        color: #fff;
        border-radius: 6px;
        padding: 8px 14px;
        font-weight: 600;
        cursor: pointer;
      }
      .xdr-defense-btn:hover { background: var(--xdr-primary-strong); border-color: var(--xdr-primary-strong); }
      .xdr-defense-btn.secondary { border-color: #5e6b7f; background: #5e6b7f; }
      .xdr-defense-btn.secondary:hover { border-color: #4f5a6a; background: #4f5a6a; }
      .xdr-defense-btn.danger { border-color: #b42318; background: #b42318; }
      .xdr-defense-btn.danger:hover { border-color: #912018; background: #912018; }
      .xdr-defense-btn:disabled { cursor: not-allowed; opacity: 0.6; }
      .xdr-defense-inline-error { color: #b91c1c; margin-top: 6px; }
      .xdr-drawer-backdrop { position: fixed; inset: 0; background: rgba(17, 24, 39, 0.35); opacity: 0; visibility: hidden; transition: opacity 180ms ease; z-index: 1000; }
      .xdr-drawer-backdrop.open { opacity: 1; visibility: visible; }
      .xdr-drawer {
        position: fixed;
        right: 0;
        top: 0;
        width: min(560px, 96vw);
        height: 100vh;
        background: #fff;
        border-left: 1px solid var(--xdr-border);
        box-shadow: -8px 0 24px rgba(15, 23, 42, 0.16);
        transform: translateX(100%);
        transition: transform 200ms ease;
        z-index: 1001;
        display: flex;
        flex-direction: column;
      }
      .xdr-drawer.open { transform: translateX(0); }
      .xdr-drawer-header { padding: 14px 16px; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; }
      .xdr-drawer-body { padding: 16px; overflow-y: auto; }
      @media (max-width: 768px) {
        .xdr-defense-app { padding: 12px; border-radius: 0; border-left: 0; border-right: 0; }
        .xdr-defense-app h1 { font-size: 27px; }
        .xdr-defense-table th, .xdr-defense-table td { font-size: 12px; }
      }
    `;
    return style;
  }

  private renderScaffold(): HTMLElement {
    const app = document.createElement('div');
    app.className = 'xdr-defense-app';
    app.innerHTML = `
      <h1>XDR Defense</h1>
      <p class="xdr-defense-subtitle">Detection content, policy rollout, and artifact management for protected endpoints.</p>
      <div id="xdr-defense-banner" class="xdr-defense-banner"></div>
      <div class="xdr-defense-tabs">
        <button class="xdr-defense-tab active" data-tab="detection-content">Yara</button>
        <button class="xdr-defense-tab" data-tab="hashes">Hashes</button>
        <button class="xdr-defense-tab" data-tab="behavioral-rules">Behavioral Rules</button>
        <button class="xdr-defense-tab" data-tab="bundle-status">Bundle Status</button>
        <button class="xdr-defense-tab" data-tab="testing">Testing</button>
        <button class="xdr-defense-tab" data-tab="correlation-ux">Correlation UX</button>
      </div>
      <div id="xdr-defense-panel" class="xdr-defense-panel"></div>
    `;

    this.bannerEl = app.querySelector('#xdr-defense-banner') as HTMLElement;
    const tabs = app.querySelectorAll('.xdr-defense-tab');
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const next = tab.getAttribute('data-tab') ?? 'detection-content';
        this.activeTab = next;
        tabs.forEach((entry) => entry.classList.remove('active'));
        tab.classList.add('active');
        this.renderTab();
      });
    });

    return app;
  }

  private showBanner(kind: 'success' | 'error', message: string): void {
    if (!this.bannerEl) {
      return;
    }
    this.bannerEl.className = `xdr-defense-banner ${kind}`;
    this.bannerEl.textContent = message;
  }

  private clearBanner(): void {
    if (!this.bannerEl) {
      return;
    }
    this.bannerEl.className = 'xdr-defense-banner';
    this.bannerEl.textContent = '';
  }

  private async refreshYaraRules(): Promise<void> {
    try {
      const payload = (await this.http.get('/api/xdr-defense/yara/rules')) as RulesResponse;
      this.yaraRules = Array.isArray(payload?.rules) ? payload.rules : [];
    } catch (error: unknown) {
      this.showBanner('error', `Failed to load YARA rules: ${String((error as Error)?.message ?? error)}`);
    }
  }

  private async refreshHashRules(): Promise<void> {
    try {
      const payload = (await this.http.get('/api/xdr-defense/hashes/rules')) as RulesResponse;
      this.hashRules = Array.isArray(payload?.rules) ? payload.rules : [];
    } catch (error: unknown) {
      this.showBanner('error', `Failed to load hash rules: ${String((error as Error)?.message ?? error)}`);
    }
  }

  private async refreshBehavioralRules(): Promise<void> {
    try {
      const payload = (await this.http.get('/api/xdr-defense/behavioral/rules')) as RulesResponse;
      this.behavioralRules = Array.isArray(payload?.rules) ? payload.rules : [];
    } catch (error: unknown) {
      this.showBanner('error', `Failed to load behavioral rules: ${String((error as Error)?.message ?? error)}`);
    }
  }

  private async refreshBundleMetadata(): Promise<void> {
    try {
      const payload = (await this.http.get('/api/xdr-defense/yara/bundle?policy_id=global-default')) as SignedBundle;
      if (payload && payload.manifest_version) {
        this.bundleMetadata = {
          bundle_version: payload.bundle_version,
          generated_at: payload.generated_at,
          policy_id: payload.policy_id,
          active_checksums: payload.active_checksums || [],
          rule_count: (payload.rules || []).length,
          enabled_rule_count: (payload.rules || []).filter((rule) => rule.enabled).length
        };
      }
    } catch (_error: unknown) {
      // Bundle may not exist yet.
    }
  }

  private async refreshRolloutStatus(): Promise<void> {
    try {
      const payload = (await this.http.get('/api/xdr-defense/yara/rollouts/status')) as RolloutStatusResponse;
      this.rolloutStatus = payload;
    } catch (_error: unknown) {
      this.rolloutStatus = null;
    }
  }

  private renderTab(): void {
    const panel = this.host.querySelector('#xdr-defense-panel');
    if (!panel) {
      return;
    }

    if (this.activeTab === 'detection-content') {
      panel.innerHTML = this.renderYaraPanel();
      this.bindYaraEvents();
      return;
    }

    if (this.activeTab === 'hashes') {
      panel.innerHTML = this.renderHashesPanel();
      this.bindHashEvents();
      return;
    }

    if (this.activeTab === 'behavioral-rules') {
      panel.innerHTML = this.renderBehavioralPanel();
      this.bindBehavioralEvents();
      return;
    }

    if (this.activeTab === 'bundle-status') {
      panel.innerHTML = this.renderBundleStatus();
      this.bindBundleStatusEvents();
      return;
    }

    if (this.activeTab === 'testing') {
      panel.innerHTML = this.renderTestingPanel();
      this.bindTestingEvents();
      return;
    }

    if (this.activeTab === 'correlation-ux') {
      panel.innerHTML = this.renderCorrelationPlaceholder();
    }
  }

  private renderRuleRolloutCell(ruleId: string): string {
    const status = this.rolloutStatus?.rules?.[ruleId];
    if (!status) {
      return '<span class="xdr-defense-muted">No dispatch yet</span>';
    }

    return `
      <div class="xdr-defense-row">
        <span class="xdr-defense-badge pending">pending ${status.pending}</span>
        <span class="xdr-defense-badge acknowledged">acked ${status.acknowledged}</span>
        <span class="xdr-defense-badge failed">failed ${status.failed}</span>
      </div>
      ${status.last_action ? `<div class="xdr-defense-muted">last: ${status.last_action}</div>` : ''}
    `;
  }

  private renderYaraPanel(): string {
    const rules = this.yaraRules.slice().sort((a, b) => a.name.localeCompare(b.name));
    const threatIntelFeeds = this.computeThreatIntelFeedCount();
    const rollout = this.rolloutStatus?.summary;

    const rows = rules
      .map(
        (rule) => `
        <tr>
          <td>${this.escapeHtml(rule.name)}</td>
          <td>${this.escapeHtml(rule.source)}</td>
          <td>${this.escapeHtml(rule.severity)}</td>
          <td>${this.escapeHtml(rule.tags.join(', '))}</td>
          <td><span class="xdr-defense-badge ${rule.validation.status}">${rule.validation.status}</span></td>
          <td>
            <label>
              <input data-yara-toggle-id="${rule.id}" type="checkbox" ${rule.enabled ? 'checked' : ''} ${
          rule.validation.status === 'invalid' ? 'disabled' : ''
        }>
              enabled
            </label>
          </td>
          <td>${this.renderRuleRolloutCell(rule.id)}</td>
          <td>${new Date(rule.updatedAt).toLocaleString()}</td>
          <td>
            ${
              rule.source !== 'builtin'
                ? `<button class="xdr-defense-btn danger" data-yara-delete-id="${rule.id}">Delete</button>`
                : '<span class="xdr-defense-muted">builtin</span>'
            }
            ${
              rule.validation.errors.length > 0
                ? `<div class="xdr-defense-inline-error">${this.escapeHtml(rule.validation.errors.join('; '))}</div>`
                : ''
            }
          </td>
        </tr>
      `
      )
      .join('');

    const failures = this.rolloutStatus?.failures ?? [];
    const failureRows = failures
      .map(
        (entry) => `
      <tr>
        <td>${this.escapeHtml(entry.agent_hostname || entry.agent_id)}</td>
        <td>${this.escapeHtml(entry.rule_name)}</td>
        <td>${entry.action}</td>
        <td><span class="xdr-defense-badge ${entry.status}">${entry.status}</span></td>
        <td>${entry.attempts}</td>
        <td>${new Date(entry.last_dispatched_at).toLocaleString()}</td>
        <td>${this.escapeHtml(entry.failure_reason || 'No ACK yet')}</td>
      </tr>
    `
      )
      .join('');

    const drawerClass = this.drawerOpen === 'yara' ? 'open' : '';

    return `
      <h2>Yara</h2>
      <div class="xdr-defense-grid">
        <div class="xdr-defense-card"><strong>Total Yara Rules</strong><div>${this.yaraRules.length}</div></div>
        <div class="xdr-defense-card"><strong>Total Behavioral Rules</strong><div>${this.behavioralRules.length}</div></div>
        <div class="xdr-defense-card"><strong>Hash Reputation Set</strong><div>${this.hashRules.length}</div></div>
        <div class="xdr-defense-card"><strong>Threat Intel Package</strong><div>${threatIntelFeeds} feeds</div></div>
      </div>

      <div class="xdr-defense-card" style="margin-bottom: 16px;">
        <div class="xdr-defense-row" style="justify-content: space-between;">
          <strong>Detection Content Registry</strong>
          <div class="xdr-defense-row">
            <button id="xdr-sync-forge-core" class="xdr-defense-btn">Sync YARA Forge Core</button>
            <button id="xdr-open-yara-drawer" class="xdr-defense-btn secondary">Add Custom Content</button>
          </div>
        </div>
        <p class="xdr-defense-muted">Sync uses bounded parallel workers and queues rollout commands for enrolled agents.</p>
      </div>

      <table class="xdr-defense-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Tags</th>
            <th>Validation</th>
            <th>State</th>
            <th>Rollout</th>
            <th>Updated</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>

      <div class="xdr-defense-card" style="margin-top: 16px;">
        <div class="xdr-defense-row" style="justify-content: space-between;">
          <h3 style="margin: 0;">YARA Rollout Failure Monitor</h3>
          <div class="xdr-defense-row">
            <button id="xdr-retry-rollout" class="xdr-defense-btn secondary">Retry Pending Failures</button>
            <span class="xdr-defense-muted">
              pending ${rollout?.pending ?? 0} | acked ${rollout?.acknowledged ?? 0} | failed ${rollout?.failed ?? 0} | retryable ${rollout?.retryable ?? 0}
            </span>
          </div>
        </div>
        ${
          failures.length === 0
            ? '<p class="xdr-defense-muted">No rollout failures detected. Commands are either acknowledged or still within ACK timeout.</p>'
            : `<table class="xdr-defense-table"><thead><tr><th>Agent</th><th>Rule</th><th>Action</th><th>Status</th><th>Attempts</th><th>Last Dispatch</th><th>Reason</th></tr></thead><tbody>${failureRows}</tbody></table>`
        }
      </div>

      ${this.renderDrawer(
        'yara',
        drawerClass,
        'Add Custom YARA Content',
        'xdr-add-yara',
        'rule my_rule {\n  strings:\n    $a = "sample"\n  condition:\n    $a\n}'
      )}
    `;
  }

  private renderHashesPanel(): string {
    const rules = this.hashRules.slice().sort((a, b) => a.name.localeCompare(b.name));

    const rows = rules
      .map(
        (rule) => `
        <tr>
          <td>${this.escapeHtml(rule.name)}</td>
          <td>${this.escapeHtml(rule.source)}</td>
          <td>${this.escapeHtml(rule.severity)}</td>
          <td>${this.escapeHtml(rule.tags.join(', '))}</td>
          <td><span class="xdr-defense-badge ${rule.validation.status}">${rule.validation.status}</span></td>
          <td>
            <label>
              <input data-hash-toggle-id="${rule.id}" type="checkbox" ${rule.enabled ? 'checked' : ''} ${
          rule.validation.status === 'invalid' ? 'disabled' : ''
        }>
              enabled
            </label>
          </td>
          <td>${new Date(rule.updatedAt).toLocaleString()}</td>
          <td>
            <button class="xdr-defense-btn danger" data-hash-delete-id="${rule.id}">Delete</button>
            ${
              rule.validation.errors.length > 0
                ? `<div class="xdr-defense-inline-error">${this.escapeHtml(rule.validation.errors.join('; '))}</div>`
                : ''
            }
          </td>
        </tr>
      `
      )
      .join('');

    const drawerClass = this.drawerOpen === 'hashes' ? 'open' : '';

    return `
      <h2>Hashes</h2>
      <div class="xdr-defense-card" style="margin-bottom: 16px;">
        <div class="xdr-defense-row" style="justify-content: space-between;">
          <strong>Hash Reputation Registry</strong>
          <div class="xdr-defense-row">
            <button id="xdr-sync-hashes" class="xdr-defense-btn">Sync MalwareBazaar Hash Feed</button>
            <button id="xdr-open-hash-drawer" class="xdr-defense-btn secondary">Add Custom Hashes</button>
          </div>
        </div>
        <p class="xdr-defense-muted">Manage hash reputation entries with deterministic validation and signed bundle output.</p>
      </div>

      <table class="xdr-defense-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Tags</th>
            <th>Validation</th>
            <th>State</th>
            <th>Updated</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>

      ${this.renderDrawer(
        'hashes',
        drawerClass,
        'Add Custom Hash Content',
        'xdr-add-hash',
        'sha256:6f2af3f7d9da2e9b9841c843f4f89d8f22d3a3f75cc9e70b2dd76378905c37da\nmd5:d41d8cd98f00b204e9800998ecf8427e'
      )}
    `;
  }

  private renderBehavioralPanel(): string {
    const rules = this.behavioralRules.slice().sort((a, b) => a.name.localeCompare(b.name));

    const rows = rules
      .map(
        (rule) => `
        <tr>
          <td>${this.escapeHtml(rule.name)}</td>
          <td>${this.escapeHtml(rule.source)}</td>
          <td>${this.escapeHtml(rule.severity)}</td>
          <td>${this.escapeHtml(rule.tags.join(', '))}</td>
          <td><span class="xdr-defense-badge ${rule.validation.status}">${rule.validation.status}</span></td>
          <td>
            <label>
              <input data-behavior-toggle-id="${rule.id}" type="checkbox" ${rule.enabled ? 'checked' : ''} ${
          rule.validation.status === 'invalid' ? 'disabled' : ''
        }>
              enabled
            </label>
          </td>
          <td>${new Date(rule.updatedAt).toLocaleString()}</td>
          <td>
            <button class="xdr-defense-btn danger" data-behavior-delete-id="${rule.id}">Delete</button>
            ${
              rule.validation.errors.length > 0
                ? `<div class="xdr-defense-inline-error">${this.escapeHtml(rule.validation.errors.join('; '))}</div>`
                : ''
            }
          </td>
        </tr>
      `
      )
      .join('');

    const drawerClass = this.drawerOpen === 'behavioral' ? 'open' : '';

    return `
      <h2>Behavioral Rules</h2>
      <div class="xdr-defense-card" style="margin-bottom: 16px;">
        <div class="xdr-defense-row" style="justify-content: space-between;">
          <strong>Behavioral Rule Registry</strong>
          <div class="xdr-defense-row">
            <button id="xdr-sync-behavioral" class="xdr-defense-btn">Sync SigmaHQ Rules</button>
            <button id="xdr-open-behavioral-drawer" class="xdr-defense-btn secondary">Add Custom Behavioral Rule</button>
          </div>
        </div>
        <p class="xdr-defense-muted">Maintain Sigma-style detection content with the same lifecycle controls as YARA and hashes.</p>
      </div>

      <table class="xdr-defense-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Tags</th>
            <th>Validation</th>
            <th>State</th>
            <th>Updated</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>

      ${this.renderDrawer(
        'behavioral',
        drawerClass,
        'Add Custom Behavioral Rule',
        'xdr-add-behavioral',
        'title: Suspicious Process Pattern\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: "-EncodedCommand"\n  condition: selection'
      )}
    `;
  }

  private renderDrawer(
    mode: 'yara' | 'hashes' | 'behavioral',
    drawerClass: string,
    title: string,
    idPrefix: string,
    placeholder: string
  ): string {
    return `
      <div id="xdr-drawer-backdrop-${mode}" class="xdr-drawer-backdrop ${drawerClass}"></div>
      <aside id="xdr-drawer-${mode}" class="xdr-drawer ${drawerClass}">
        <div class="xdr-drawer-header">
          <strong>${title}</strong>
          <button data-close-drawer="${mode}" class="xdr-defense-btn secondary">Close</button>
        </div>
        <div class="xdr-drawer-body">
          <div class="xdr-defense-row">
            <div style="flex: 1 1 220px;">
              <label>Name</label>
              <input id="${idPrefix}-name" class="xdr-defense-input" placeholder="rule name">
            </div>
            <div style="width: 180px;">
              <label>Severity</label>
              <select id="${idPrefix}-severity" class="xdr-defense-select">
                <option value="low">low</option>
                <option value="medium" selected>medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </div>
          </div>
          <div style="margin-top: 10px;">
            <label>Tags (comma-separated)</label>
            <input id="${idPrefix}-tags" class="xdr-defense-input" placeholder="malware, custom">
          </div>
          <div style="margin-top: 10px;">
            <label>Rule Content</label>
            <textarea id="${idPrefix}-content" class="xdr-defense-textarea" placeholder="${this.escapeHtml(placeholder)}"></textarea>
          </div>
          <div style="margin-top: 10px;" class="xdr-defense-row">
            <button id="${idPrefix}-submit" class="xdr-defense-btn">Add Rule</button>
          </div>
        </div>
      </aside>
    `;
  }

  private renderCorrelationPlaceholder(): string {
    return `
      <h2>Correlation UX</h2>
      <p>This first version keeps correlation lightweight and focused on guidance.</p>
      <div class="xdr-defense-card">
        <p><strong>Status:</strong> agent handles single-event detections; OpenSearch handles time-window correlation.</p>
        <p><strong>Guidance:</strong> keep signatures deterministic and aggregate suspicious patterns in OpenSearch correlation rules by host, process ancestry, and user context.</p>
        <p class="xdr-defense-muted">No heavy backend work is wired for this tab yet.</p>
      </div>
    `;
  }

  private renderBundleStatus(): string {
    if (!this.bundleMetadata) {
      return `
        <h2>Bundle Status & Rollout</h2>
        <div class="xdr-defense-card">
          <p><strong>Current Status:</strong> No YARA bundle generated yet.</p>
          <p>After adding or syncing YARA rules, build and sign a bundle for agent consumption.</p>
        </div>
        <button id="xdr-build-bundle" class="xdr-defense-btn">Build & Sign Bundle</button>
      `;
    }

    const metadata = this.bundleMetadata;
    return `
      <h2>Bundle Status & Rollout</h2>
      <div class="xdr-defense-grid">
        <div class="xdr-defense-card">
          <strong>Bundle Version</strong>
          <div>${metadata.bundle_version}</div>
        </div>
        <div class="xdr-defense-card">
          <strong>Generated</strong>
          <div>${new Date(metadata.generated_at).toLocaleString()}</div>
        </div>
        <div class="xdr-defense-card">
          <strong>Total Rules</strong>
          <div>${metadata.rule_count}</div>
        </div>
        <div class="xdr-defense-card">
          <strong>Enabled Rules</strong>
          <div>${metadata.enabled_rule_count}</div>
        </div>
      </div>
      <div class="xdr-defense-card" style="margin: 16px 0;">
        <h3>Bundle Info</h3>
        <p><span class="xdr-defense-muted">Policy ID:</span> ${this.escapeHtml(metadata.policy_id)}</p>
        <p><span class="xdr-defense-muted">Active Checksums:</span> ${metadata.active_checksums.length} rules signed</p>
        ${metadata.activated_at ? `<p><span class="xdr-defense-muted">Activated:</span> ${new Date(metadata.activated_at).toLocaleString()}</p>` : ''}
      </div>
      <div class="xdr-defense-row">
        <button id="xdr-build-bundle" class="xdr-defense-btn">Rebuild Bundle</button>
        <button id="xdr-view-bundle" class="xdr-defense-btn secondary">View Manifest</button>
      </div>
    `;
  }

  private bindYaraEvents(): void {
    const syncButton = this.host.querySelector('#xdr-sync-forge-core');
    syncButton?.addEventListener('click', async () => {
      this.clearBanner();
      try {
        const result = (await this.http.post('/api/xdr-defense/yara/forge-core/sync', {
          body: JSON.stringify({})
        })) as {
          parallel_workers: number;
          imported: number;
          unchanged: number;
          load_failures: number;
          rollout: { created: number; deduplicated: number };
          errors: string[];
        };

        await this.refreshAll();
        this.renderTab();
        const errorText = Array.isArray(result.errors) && result.errors.length > 0 ? `\nErrors:\n${result.errors.join('\n')}` : '';
        this.showBanner(
          'success',
          `Forge sync completed with ${result.parallel_workers} workers. Imported ${result.imported}, unchanged ${result.unchanged}, load failures ${result.load_failures}. Rollout created ${result.rollout?.created ?? 0}, deduplicated ${result.rollout?.deduplicated ?? 0}.${errorText}`
        );
      } catch (error: unknown) {
        this.showBanner('error', `Failed to sync YARA Forge Core: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const retryButton = this.host.querySelector('#xdr-retry-rollout');
    retryButton?.addEventListener('click', async () => {
      this.clearBanner();
      try {
        const result = (await this.http.post('/api/xdr-defense/yara/rollouts/retry', {
          body: JSON.stringify({})
        })) as { retried: number };

        await this.refreshRolloutStatus();
        this.renderTab();
        this.showBanner('success', `Retried ${result.retried} rollout command(s).`);
      } catch (error: unknown) {
        this.showBanner('error', `Failed to retry rollout failures: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const openDrawer = this.host.querySelector('#xdr-open-yara-drawer');
    openDrawer?.addEventListener('click', () => {
      this.drawerOpen = 'yara';
      this.renderTab();
    });

    this.bindDrawerClose('yara');

    const addButton = this.host.querySelector('#xdr-add-yara-submit');
    addButton?.addEventListener('click', async () => {
      this.clearBanner();
      const nameInput = this.host.querySelector('#xdr-add-yara-name') as HTMLInputElement;
      const contentInput = this.host.querySelector('#xdr-add-yara-content') as HTMLTextAreaElement;
      const severityInput = this.host.querySelector('#xdr-add-yara-severity') as HTMLSelectElement;
      const tagsInput = this.host.querySelector('#xdr-add-yara-tags') as HTMLInputElement;

      try {
        await this.http.post('/api/xdr-defense/yara/rules', {
          body: JSON.stringify({
            name: nameInput.value,
            content: contentInput.value,
            severity: severityInput.value,
            tags: tagsInput.value
              .split(',')
              .map((entry) => entry.trim())
              .filter((entry) => entry.length > 0)
          })
        });
        this.drawerOpen = 'none';
        await this.refreshAll();
        this.renderTab();
        this.showBanner('success', 'Custom YARA rule added and rollout queued for enrolled agents.');
      } catch (error: unknown) {
        this.showBanner('error', `Failed to add YARA rule: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const toggleInputs = this.host.querySelectorAll('[data-yara-toggle-id]');
    toggleInputs.forEach((node) => {
      node.addEventListener('change', async () => {
        const element = node as HTMLInputElement;
        const id = element.getAttribute('data-yara-toggle-id') ?? '';
        try {
          await this.http.put(`/api/xdr-defense/yara/rules/${encodeURIComponent(id)}`, {
            body: JSON.stringify({ enabled: element.checked })
          });
          await this.refreshAll();
          this.renderTab();
          this.showBanner('success', 'YARA rule state updated and rollout command queued.');
        } catch (error: unknown) {
          this.showBanner('error', `Failed to update YARA rule: ${String((error as Error)?.message ?? error)}`);
          await this.refreshAll();
          this.renderTab();
        }
      });
    });

    const deleteButtons = this.host.querySelectorAll('[data-yara-delete-id]');
    deleteButtons.forEach((node) => {
      node.addEventListener('click', async () => {
        const id = node.getAttribute('data-yara-delete-id') ?? '';
        if (!window.confirm('Delete this YARA rule from registry?')) {
          return;
        }
        try {
          await this.http.delete(`/api/xdr-defense/yara/rules/${encodeURIComponent(id)}`);
          await this.refreshAll();
          this.renderTab();
          this.showBanner('success', 'YARA rule deleted and rollout command queued.');
        } catch (error: unknown) {
          this.showBanner('error', `Failed to delete YARA rule: ${String((error as Error)?.message ?? error)}`);
        }
      });
    });
  }

  private bindHashEvents(): void {
    const syncButton = this.host.querySelector('#xdr-sync-hashes');
    syncButton?.addEventListener('click', async () => {
      this.clearBanner();
      try {
        const result = (await this.http.post('/api/xdr-defense/hashes/open-source/sync', {
          body: JSON.stringify({})
        })) as {
          parallel_workers: number;
          imported: number;
          unchanged: number;
          load_failures: number;
          errors: string[];
        };
        await this.refreshHashRules();
        await this.refreshYaraRules();
        this.renderTab();
        const errorText = Array.isArray(result.errors) && result.errors.length > 0 ? `\nErrors:\n${result.errors.join('\n')}` : '';
        this.showBanner(
          'success',
          `Hash feed sync completed with ${result.parallel_workers} workers. Imported ${result.imported}, unchanged ${result.unchanged}, load failures ${result.load_failures}.${errorText}`
        );
      } catch (error: unknown) {
        this.showBanner('error', `Failed to sync open-source hashes: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const openDrawer = this.host.querySelector('#xdr-open-hash-drawer');
    openDrawer?.addEventListener('click', () => {
      this.drawerOpen = 'hashes';
      this.renderTab();
    });

    this.bindDrawerClose('hashes');

    const addButton = this.host.querySelector('#xdr-add-hash-submit');
    addButton?.addEventListener('click', async () => {
      this.clearBanner();
      const nameInput = this.host.querySelector('#xdr-add-hash-name') as HTMLInputElement;
      const contentInput = this.host.querySelector('#xdr-add-hash-content') as HTMLTextAreaElement;
      const severityInput = this.host.querySelector('#xdr-add-hash-severity') as HTMLSelectElement;
      const tagsInput = this.host.querySelector('#xdr-add-hash-tags') as HTMLInputElement;

      try {
        await this.http.post('/api/xdr-defense/hashes/rules', {
          body: JSON.stringify({
            name: nameInput.value,
            content: contentInput.value,
            severity: severityInput.value,
            tags: tagsInput.value
              .split(',')
              .map((entry) => entry.trim())
              .filter((entry) => entry.length > 0)
          })
        });
        this.drawerOpen = 'none';
        await this.refreshHashRules();
        this.renderTab();
        this.showBanner('success', 'Custom hash content added.');
      } catch (error: unknown) {
        this.showBanner('error', `Failed to add hash content: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const toggleInputs = this.host.querySelectorAll('[data-hash-toggle-id]');
    toggleInputs.forEach((node) => {
      node.addEventListener('change', async () => {
        const element = node as HTMLInputElement;
        const id = element.getAttribute('data-hash-toggle-id') ?? '';
        try {
          await this.http.put(`/api/xdr-defense/hashes/rules/${encodeURIComponent(id)}`, {
            body: JSON.stringify({ enabled: element.checked })
          });
          await this.refreshHashRules();
          this.renderTab();
          this.showBanner('success', 'Hash rule state updated.');
        } catch (error: unknown) {
          this.showBanner('error', `Failed to update hash rule: ${String((error as Error)?.message ?? error)}`);
          await this.refreshHashRules();
          this.renderTab();
        }
      });
    });

    const deleteButtons = this.host.querySelectorAll('[data-hash-delete-id]');
    deleteButtons.forEach((node) => {
      node.addEventListener('click', async () => {
        const id = node.getAttribute('data-hash-delete-id') ?? '';
        if (!window.confirm('Delete this hash rule from registry?')) {
          return;
        }
        try {
          await this.http.delete(`/api/xdr-defense/hashes/rules/${encodeURIComponent(id)}`);
          await this.refreshHashRules();
          this.renderTab();
          this.showBanner('success', 'Hash rule deleted.');
        } catch (error: unknown) {
          this.showBanner('error', `Failed to delete hash rule: ${String((error as Error)?.message ?? error)}`);
        }
      });
    });
  }

  private bindBehavioralEvents(): void {
    const syncButton = this.host.querySelector('#xdr-sync-behavioral');
    syncButton?.addEventListener('click', async () => {
      this.clearBanner();
      try {
        const result = (await this.http.post('/api/xdr-defense/behavioral/open-source/sync', {
          body: JSON.stringify({})
        })) as {
          parallel_workers: number;
          imported: number;
          unchanged: number;
          load_failures: number;
          errors: string[];
        };
        await this.refreshBehavioralRules();
        await this.refreshYaraRules();
        this.renderTab();
        const errorText = Array.isArray(result.errors) && result.errors.length > 0 ? `\nErrors:\n${result.errors.join('\n')}` : '';
        this.showBanner(
          'success',
          `SigmaHQ sync completed with ${result.parallel_workers} workers. Imported ${result.imported}, unchanged ${result.unchanged}, load failures ${result.load_failures}.${errorText}`
        );
      } catch (error: unknown) {
        this.showBanner('error', `Failed to sync SigmaHQ rules: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const openDrawer = this.host.querySelector('#xdr-open-behavioral-drawer');
    openDrawer?.addEventListener('click', () => {
      this.drawerOpen = 'behavioral';
      this.renderTab();
    });

    this.bindDrawerClose('behavioral');

    const addButton = this.host.querySelector('#xdr-add-behavioral-submit');
    addButton?.addEventListener('click', async () => {
      this.clearBanner();
      const nameInput = this.host.querySelector('#xdr-add-behavioral-name') as HTMLInputElement;
      const contentInput = this.host.querySelector('#xdr-add-behavioral-content') as HTMLTextAreaElement;
      const severityInput = this.host.querySelector('#xdr-add-behavioral-severity') as HTMLSelectElement;
      const tagsInput = this.host.querySelector('#xdr-add-behavioral-tags') as HTMLInputElement;

      try {
        await this.http.post('/api/xdr-defense/behavioral/rules', {
          body: JSON.stringify({
            name: nameInput.value,
            content: contentInput.value,
            severity: severityInput.value,
            tags: tagsInput.value
              .split(',')
              .map((entry) => entry.trim())
              .filter((entry) => entry.length > 0)
          })
        });
        this.drawerOpen = 'none';
        await this.refreshBehavioralRules();
        this.renderTab();
        this.showBanner('success', 'Custom behavioral rule added.');
      } catch (error: unknown) {
        this.showBanner('error', `Failed to add behavioral rule: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const toggleInputs = this.host.querySelectorAll('[data-behavior-toggle-id]');
    toggleInputs.forEach((node) => {
      node.addEventListener('change', async () => {
        const element = node as HTMLInputElement;
        const id = element.getAttribute('data-behavior-toggle-id') ?? '';
        try {
          await this.http.put(`/api/xdr-defense/behavioral/rules/${encodeURIComponent(id)}`, {
            body: JSON.stringify({ enabled: element.checked })
          });
          await this.refreshBehavioralRules();
          this.renderTab();
          this.showBanner('success', 'Behavioral rule state updated.');
        } catch (error: unknown) {
          this.showBanner('error', `Failed to update behavioral rule: ${String((error as Error)?.message ?? error)}`);
          await this.refreshBehavioralRules();
          this.renderTab();
        }
      });
    });

    const deleteButtons = this.host.querySelectorAll('[data-behavior-delete-id]');
    deleteButtons.forEach((node) => {
      node.addEventListener('click', async () => {
        const id = node.getAttribute('data-behavior-delete-id') ?? '';
        if (!window.confirm('Delete this behavioral rule from registry?')) {
          return;
        }
        try {
          await this.http.delete(`/api/xdr-defense/behavioral/rules/${encodeURIComponent(id)}`);
          await this.refreshBehavioralRules();
          this.renderTab();
          this.showBanner('success', 'Behavioral rule deleted.');
        } catch (error: unknown) {
          this.showBanner('error', `Failed to delete behavioral rule: ${String((error as Error)?.message ?? error)}`);
        }
      });
    });
  }

  private bindDrawerClose(mode: 'yara' | 'hashes' | 'behavioral'): void {
    const closeButton = this.host.querySelector(`[data-close-drawer="${mode}"]`);
    closeButton?.addEventListener('click', () => {
      this.drawerOpen = 'none';
      this.renderTab();
    });

    const backdrop = this.host.querySelector(`#xdr-drawer-backdrop-${mode}`);
    backdrop?.addEventListener('click', () => {
      this.drawerOpen = 'none';
      this.renderTab();
    });
  }

  private bindBundleStatusEvents(): void {
    const buildButton = this.host.querySelector('#xdr-build-bundle');
    buildButton?.addEventListener('click', async () => {
      this.clearBanner();
      try {
        const response = (await this.http.post('/api/xdr-defense/yara/bundle/build', {
          body: JSON.stringify({ policy_id: 'global-default' })
        })) as SignedBundle | { bundle?: SignedBundle };

        const bundle = (response as { bundle?: SignedBundle }).bundle ?? (response as SignedBundle);
        this.showBanner('success', `Bundle built and signed: version ${bundle.bundle_version}`);
        await this.refreshBundleMetadata();
        this.renderTab();
      } catch (error: unknown) {
        this.showBanner('error', `Failed to build bundle: ${String((error as Error)?.message ?? error)}`);
      }
    });

    const viewButton = this.host.querySelector('#xdr-view-bundle');
    viewButton?.addEventListener('click', async () => {
      this.clearBanner();
      try {
        const result = (await this.http.get('/api/xdr-defense/yara/bundle?policy_id=global-default')) as SignedBundle;
        const manifest = {
          manifest_version: result.manifest_version,
          policy_id: result.policy_id,
          bundle_version: result.bundle_version,
          generated_at: result.generated_at,
          signing_alg: result.signing_alg,
          rule_count: result.rules.length,
          active_checksums: result.active_checksums
        };
        this.showBanner('success', `Bundle manifest:\n${JSON.stringify(manifest, null, 2)}`);
      } catch (error: unknown) {
        this.showBanner('error', `Failed to view bundle: ${String((error as Error)?.message ?? error)}`);
      }
    });
  }

  private renderTestingPanel(): string {
    return `
      <h2>YARA Testing</h2>
      <div class="xdr-defense-row">
        <div style="flex: 1 1 280px;">
          <label>Sample Text (optional)</label>
          <input id="xdr-test-sample" class="xdr-defense-input" placeholder="string to match in recent docs">
        </div>
        <div style="width: 180px;">
          <label>Lookback Minutes</label>
          <input id="xdr-test-lookback" class="xdr-defense-input" type="number" min="1" max="10080" value="60">
        </div>
      </div>
      <div style="margin-top: 10px;">
        <label>Rule Content</label>
        <textarea id="xdr-test-content" class="xdr-defense-textarea" placeholder="rule test_rule { ... }"></textarea>
      </div>
      <div style="margin-top: 10px;" class="xdr-defense-row">
        <button id="xdr-test-submit" class="xdr-defense-btn">Run Test</button>
      </div>
      <pre id="xdr-test-output" class="xdr-defense-card" style="margin-top: 12px; white-space: pre-wrap;">No test run yet.</pre>
    `;
  }

  private bindTestingEvents(): void {
    const testButton = this.host.querySelector('#xdr-test-submit');
    testButton?.addEventListener('click', async () => {
      this.clearBanner();
      const content = (this.host.querySelector('#xdr-test-content') as HTMLTextAreaElement).value;
      const sampleText = (this.host.querySelector('#xdr-test-sample') as HTMLInputElement).value;
      const lookbackInput = this.host.querySelector('#xdr-test-lookback') as HTMLInputElement;
      const lookback = Number(lookbackInput.value || '60');
      const output = this.host.querySelector('#xdr-test-output') as HTMLElement;

      try {
        const result = (await this.http.post('/api/xdr-defense/yara/test', {
          body: JSON.stringify({
            content,
            sample_text: sampleText,
            lookback_minutes: lookback
          })
        })) as YaraTestResponse;

        output.textContent = JSON.stringify(result, null, 2);
      } catch (error: unknown) {
        output.textContent = `Test failed: ${String((error as Error)?.message ?? error)}`;
      }
    });
  }

  private computeThreatIntelFeedCount(): number {
    const feeds = new Set<string>();
    if (this.yaraRules.some((rule) => rule.source === 'forge-core')) {
      feeds.add('forge-core');
    }
    if (this.hashRules.some((rule) => rule.source === 'malwarebazaar')) {
      feeds.add('malwarebazaar');
    }
    if (this.behavioralRules.some((rule) => rule.source === 'sigmahq')) {
      feeds.add('sigmahq');
    }
    return feeds.size;
  }

  private escapeHtml(input: string): string {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}

export class XdrDefensePlugin {
  public setup(core: any) {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      category: PLUGIN_CATEGORY,
      mount: async (params: any) => {
        const app = new XdrDefenseUi(params.element, core.http);
        await app.mount();

        return () => {
          params.element.innerHTML = '';
        };
      }
    });
    return {};
  }

  public start() {
    return {};
  }

  public stop() {}
}
