export function registerRollbackRoutes(router: any) {
  router.post(
    {
      path: '/api/xdr-defense/rollback/confirm',
      validate: false
    },
    async (_ctx: unknown, req: any, res: any) => {
      return res.ok({
        body: {
          status: 'confirmed',
          agent_id: req.body?.agent_id,
          incident_id: req.body?.incident_id,
          confirmed_at: new Date().toISOString()
        }
      });
    }
  );
}
