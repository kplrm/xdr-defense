export interface YaraRule {
  name: string;
  tags: string[];
  description: string;
  author: string;
  reference: string;
  content: string;
}

export interface CatalogMetadata {
  source: string;
  version: string;
  platform: string;
  rules_sha256: string;
  source_sha256: string;
  rule_count: number;
}

export interface RuleCatalog extends CatalogMetadata { rules: YaraRule[]; }
export interface RulesResponse extends CatalogMetadata {
  rules: Array<Omit<YaraRule, 'content'>>;
  total: number;
  page: number;
  perPage: number;
}

export interface AgentProtection {
  rule_source: string;
  rule_version: string;
  rule_count: number;
  mode: string;
  platform: string;
  rules_sha256: string;
  health?: Record<string, string>;
}

export interface AgentInventory {
  agent_id: string;
  name: string;
  status: string;
  version: string;
  last_seen?: string;
  protection?: AgentProtection;
}

// A release name alone cannot establish which rules the endpoint has loaded.
export function matchesCatalog(protection: AgentProtection | undefined, catalog: CatalogMetadata): boolean {
  return Boolean(protection && protection.platform === catalog.platform &&
    protection.rules_sha256 === catalog.rules_sha256 && protection.rule_count === catalog.rule_count);
}
