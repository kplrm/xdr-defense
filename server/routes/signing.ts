import { getSigningPublicKey } from '../lib/signing_keys';

export function registerSigningRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr-defense/signing/public-key',
      options: {
        authRequired: false
      },
      validate: false
    },
    async (_ctx: unknown, _req: unknown, res: any) => {
      try {
        const publicKey = getSigningPublicKey();
        if (!publicKey.ok || !publicKey.public_key_b64 || !publicKey.source || !publicKey.key_id) {
          return res.customError({
            statusCode: 503,
            body: {
              message: 'Signing public key is unavailable.',
              details: publicKey.error ?? 'Key provider returned no key material.'
            }
          });
        }

        return res.ok({
          body: {
            public_key_b64: publicKey.public_key_b64,
            source: publicKey.source,
            key_id: publicKey.key_id
          }
        });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: {
            message: 'Failed to resolve signing public key.',
            details: String(err?.message ?? err)
          }
        });
      }
    }
  );
}
