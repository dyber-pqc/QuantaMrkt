import type { APIRoute } from 'astro';
import { getModelBySlug } from '../../../../lib/db';

export const GET: APIRoute = async ({ params, locals }) => {
  try {
    const slug = params.slug;
    if (!slug) {
      return new Response(JSON.stringify({ error: 'Missing slug parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const model = await getModelBySlug(db, slug);

    if (!model) {
      return new Response(JSON.stringify({ error: 'Model not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const verified = model.signatures.length > 0;

    return new Response(
      JSON.stringify({
        verified,
        signatures: model.signatures.map((s) => ({
          signer_did: s.signer_did,
          algorithm: s.algorithm,
          attestation_type: s.attestation_type,
          signed_at: s.signed_at,
        })),
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
