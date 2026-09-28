import React, { useCallback, useEffect, useState } from 'react';
import {
  EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiCodeBlock,
  EuiFieldSearch, EuiFlexGroup, EuiFlexItem, EuiFlyout, EuiFlyoutBody,
  EuiFlyoutHeader, EuiFormRow, EuiLoadingSpinner, EuiPanel, EuiSelect,
  EuiSpacer, EuiText, EuiTitle,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';
import { AgentInventory, matchesCatalog, RulesResponse, YaraRule } from '../../common/inventory';

interface Props { http: CoreStart['http']; }

export const ProtectionInventory = ({ http }: Props) => {
  const [agents, setAgents] = useState<AgentInventory[]>([]);
  const [agentId, setAgentId] = useState('');
  const [catalog, setCatalog] = useState<RulesResponse>();
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [fleetError, setFleetError] = useState('');
  const [detail, setDetail] = useState<YaraRule>();

  useEffect(() => {
    let active = true;
    http.get<{ agents: AgentInventory[] }>('/api/xdr_manager/protections')
      .then((result) => { if (active) { setAgents(result.agents); setFleetError(''); } })
      .catch(() => { if (active) { setAgents([]); setFleetError('Agent inventory is unavailable. Check that XDR Coordinator is installed and reachable.'); } });
    return () => { active = false; };
  }, [http, refresh]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    const timer = setTimeout(() => {
      http.get<RulesResponse>('/api/xdr-defense/yara/rules', { query: { q: query, page: page + 1, perPage: 25 } })
        .then((result) => { if (active) { setCatalog(result); setError(''); } })
        .catch(() => { if (active) { setCatalog(undefined); setError('The release rule catalog could not be loaded.'); } })
        .finally(() => { if (active) setLoading(false); });
    }, 200);
    return () => { active = false; clearTimeout(timer); };
  }, [http, query, page, refresh]);

  const openRule = useCallback(async (name: string) => {
    try {
      setDetail(await http.get<YaraRule>(`/api/xdr-defense/yara/rules/${encodeURIComponent(name)}`));
    } catch {
      setError('This rule could not be loaded.');
    }
  }, [http]);

  const agent = agents.find((item) => item.agent_id === agentId);
  const installed = agent?.protection;
  const catalogAvailable = Boolean(catalog && (!agentId || (agent && matchesCatalog(installed, catalog))));
  const columns: Array<EuiBasicTableColumn<Omit<YaraRule, 'content'>>> = [
    { field: 'name', name: 'Rule', render: (name: string) => <EuiButtonEmpty size="s" onClick={() => openRule(name)}>{name}</EuiButtonEmpty> },
    { field: 'description', name: 'Description', truncateText: true },
    { field: 'tags', name: 'Tags', render: (tags: string[]) => tags.join(', ') },
  ];

  return <div>
    <EuiTitle size="m"><h2>Protection inventory</h2></EuiTitle>
    <EuiText><p>Inspect the YARA Forge Core rules included in Linux agent releases and the protection inventory reported by your agents.</p></EuiText>
    <EuiSpacer />
    {error && <><EuiCallOut title={error} color="danger" /><EuiSpacer /></>}
    {fleetError && <><EuiCallOut title={fleetError} color="warning" /><EuiSpacer /></>}
    <EuiPanel>
      <EuiFlexGroup alignItems="flexEnd">
        <EuiFlexItem><EuiFormRow label="Inventory">
          <EuiSelect value={agentId} onChange={(event) => { setAgentId(event.target.value); setDetail(undefined); setPage(0); }} options={[
            { value: '', text: 'Release catalog (not an installed-agent inventory)' },
            ...agents.map((item) => ({ value: item.agent_id, text: `${item.name || item.agent_id} — ${item.status}` })),
          ]} />
        </EuiFormRow></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiButton onClick={() => setRefresh((value) => value + 1)}>Refresh inventory</EuiButton></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      {agent && <EuiText size="s"><p>
        Agent: <strong>{agent.name}</strong> · Agent version: {agent.version || 'Unknown'} · Status: {agent.status}<br />
        Last heartbeat: {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : 'Not reported'}<br />
        {installed ? <>Protection: {installed.rule_source} · Rule version: {installed.rule_version} · Rules: {installed.rule_count} · Mode: {installed.mode}<br />SHA-256: <code>{installed.rules_sha256}</code><br />{Object.entries(installed.health ?? {}).map(([name, status]) => <React.Fragment key={name}>{name}: {status}<br /></React.Fragment>)}</> : 'This agent has not reported its installed protection inventory.'}
      </p></EuiText>}
      {agentId && !catalogAvailable && !loading && <EuiCallOut color="warning" title="Rule details are unavailable for this agent">
        <p>{installed ? 'Its reported rule checksum or count differs from this Defense release catalog. Install the matching Defense catalog to inspect that release; rules are updated through agent releases.' : 'Wait for an inventory heartbeat from an agent that supports release inventory reporting.'}</p>
      </EuiCallOut>}
      {!agentId && catalog && <EuiText size="s"><p>
        Catalog: {catalog.source} · {catalog.version} · {catalog.platform} · {catalog.rule_count} rules<br />
        Select an agent to verify that this catalog matches its reported installed rules.
      </p></EuiText>}
    </EuiPanel>
    <EuiSpacer />
    {loading && <EuiLoadingSpinner />}
    {catalogAvailable && catalog && <EuiPanel>
      <EuiFormRow label="Search rules" fullWidth><EuiFieldSearch fullWidth value={query} placeholder="Name, description, author, reference or tag" onChange={(event) => { setQuery(event.target.value); setPage(0); }} /></EuiFormRow>
      <EuiSpacer />
      <EuiBasicTable<Omit<YaraRule, 'content'>> items={catalog.rules} columns={columns} loading={loading}
        pagination={{ pageIndex: page, pageSize: 25, totalItemCount: catalog.total, hidePerPageOptions: true }}
        onChange={({ page: next }: { page?: { index: number } }) => { if (next) setPage(next.index); }} />
    </EuiPanel>}
    <EuiSpacer />
    <EuiText size="s"><p>Agent releases include and update the rules. Ransomware, memory protection and behavioral rules are future work.</p></EuiText>
    {detail && <EuiFlyout onClose={() => setDetail(undefined)} aria-labelledby="rule-title" size="l">
      <EuiFlyoutHeader hasBorder><EuiTitle size="m"><h2 id="rule-title">{detail.name}</h2></EuiTitle></EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiText><p>{detail.description}</p><p>Author: {detail.author || 'Not specified'}<br />Reference: {detail.reference || 'Not specified'}<br />Tags: {detail.tags.join(', ') || 'None'}</p></EuiText>
        <EuiSpacer />
        <EuiCodeBlock language="text" isCopyable>{detail.content}</EuiCodeBlock>
      </EuiFlyoutBody>
    </EuiFlyout>}
  </div>;
};
