import { schema } from '@osd/config-schema';
import { findRule, loadCatalog, searchRules } from '../lib/inventory';

export function registerInventoryRoutes(router: any): void {
  router.get({
    path: '/api/xdr-defense/yara/rules',
    validate: { query: schema.object({
      q: schema.string({ defaultValue: '', maxLength: 500 }),
      page: schema.number({ defaultValue: 1, min: 1, max: 100000, validate: (value: number) => Number.isInteger(value) ? undefined : 'Expected an integer' }),
      perPage: schema.number({ defaultValue: 25, min: 1, max: 100, validate: (value: number) => Number.isInteger(value) ? undefined : 'Expected an integer' }),
    }) },
  }, async (_ctx: unknown, req: any, res: any) => {
    try {
      return res.ok({ body: searchRules(loadCatalog(), req.query.q, req.query.page, req.query.perPage) });
    } catch (error) {
      return res.customError({ statusCode: 503, body: { message: String(error) } });
    }
  });

  router.get({
    path: '/api/xdr-defense/yara/rules/{name}',
    validate: { params: schema.object({ name: schema.string({ minLength: 1, maxLength: 500 }) }) },
  }, async (_ctx: unknown, req: any, res: any) => {
    try {
      const rule = findRule(loadCatalog(), req.params.name);
      return rule ? res.ok({ body: rule }) : res.notFound({ body: { message: 'Rule is absent from this release catalog.' } });
    } catch (error) {
      return res.customError({ statusCode: 503, body: { message: String(error) } });
    }
  });
}
