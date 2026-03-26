import type { APIRoute } from 'astro';

/**
 * GET /.well-known/pqc-public-key
 *
 * Returns the platform ML-DSA-87 public key so anyone can independently
 * verify every PQC signature in the registry.
 */
export const GET: APIRoute = async ({ locals }) => {
  const env = (locals as any).runtime?.env ?? {};
  const publicKeyHex: string = env.PLATFORM_ML_DSA_PUBLIC_KEY || '';

  const payload = {
    algorithm: 'ML-DSA-87',
    did: 'did:web:quantamrkt.com:chain:authority',
    public_key_hex: publicKeyHex || 'NOT_YET_CONFIGURED',
    key_type: 'FIPS 204 ML-DSA-87 (Dilithium5)',
    created_at: '2026-03-26',
    usage: 'Platform model signing and chain block signatures',
    verify_endpoint: '/api/models/{slug}/verify',
    documentation: '/pqc-key',
  };

  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
    },
  });
};
