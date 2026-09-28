import { readFileSync } from 'fs';
import { resolve } from 'path';
import { RuleCatalog, RulesResponse, YaraRule } from '../../common/inventory';

let cachedCatalog: RuleCatalog | undefined;

export function loadCatalog(): RuleCatalog {
  if (!cachedCatalog) {
    const catalog: RuleCatalog = JSON.parse(readFileSync(resolve(__dirname, '../data/yara-core-linux.json'), 'utf8'));
    if (catalog.platform !== 'linux' || !/^[a-f0-9]{64}$/.test(catalog.rules_sha256) ||
        !Array.isArray(catalog.rules) || catalog.rule_count !== catalog.rules.length || !catalog.rule_count) {
      throw new Error('The bundled Linux YARA catalog is invalid. Rebuild Defense from the agent release catalog.');
    }
    cachedCatalog = catalog;
  }
  return cachedCatalog;
}

export function searchRules(catalog: RuleCatalog, query: string, page: number, perPage: number): RulesResponse {
  const { rules, ...metadata } = catalog;
  const words = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const matching = rules.filter((rule) => {
    const text = [rule.name, rule.description, rule.author, rule.reference, ...rule.tags].join(' ').toLowerCase();
    return words.every((word) => text.includes(word));
  });
  return {
    ...metadata,
    rules: matching.slice((page - 1) * perPage, page * perPage).map(({ content, ...summary }) => summary),
    total: matching.length,
    page,
    perPage,
  };
}

export function findRule(catalog: RuleCatalog, name: string): YaraRule | undefined {
  return catalog.rules.find((rule) => rule.name === name);
}
