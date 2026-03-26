import type { APIRoute } from 'astro';
import { getModelBySlug, logActivity } from '../../../../lib/db';
import { getApiUser } from '../../../../lib/api-auth';
import { appendLogEntry } from '../../../../lib/transparency';

/**
 * POST /api/models/:slug/sign
 *
 * Accepts a real PQC signature from the signing pipeline and persists it.
 *
 * Body: {
 *   signer_did:       string   (e.g. "did:web:quantamrkt.com:chain:authority")
 *   algorithm:        string   (e.g. "ML-DSA-87")
 *   signature_hex:    string   (hex-encoded ML-DSA-87 signature)
 *   attestation_type: string   (e.g. "pqc_registry")
 *   message_hash:     string   (hex SHA3-256 of the canonical message)
 *   public_key_hex:   string   (hex-encoded signer public key)
 * }
 */
export const POST: APIRoute = async ({ params, request, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

  try {
    // -- Auth ----------------------------------------------------------------
    const user = await getApiUser(locals, request);
    if (!user) {
      return json({ error: 'Unauthorized' }, 401);
    }

    // -- Params --------------------------------------------------------------
    const slug = params.slug;
    if (!slug) {
      return json({ error: 'Missing slug parameter' }, 400);
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const model = await getModelBySlug(db, slug);
    if (!model) {
      return json({ error: 'Model not found' }, 404);
    }

    // -- Body ----------------------------------------------------------------
    const body = (await request.json()) as Record<string, any>;
    const {
      signer_did,
      algorithm,
      signature_hex,
      attestation_type,
      message_hash,
      public_key_hex,
    } = body;

    if (!signer_did || !algorithm || !signature_hex || !attestation_type) {
      return json(
        { error: 'Missing required fields: signer_did, algorithm, signature_hex, attestation_type' },
        400,
      );
    }

    // -- Resolve the latest version_id --------------------------------------
    const latestVersion = model.versions?.[0];
    if (!latestVersion) {
      return json({ error: 'Model has no versions — cannot attach signature' }, 400);
    }
    const versionId = latestVersion.id;

    // -- Insert signature into D1 -------------------------------------------
    const now = new Date().toISOString().replace('T', ' ').replace('Z', '').split('.')[0];

    await db
      .prepare(
        `INSERT INTO signatures (version_id, signer_did, algorithm, signature_hex, attestation_type, signed_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(versionId, signer_did, algorithm, signature_hex, attestation_type, now)
      .run();

    // -- Mark model as verified ---------------------------------------------
    await db.prepare('UPDATE models SET verified = 1, updated_at = ? WHERE id = ?').bind(now, model.id).run();

    // -- Activity log -------------------------------------------------------
    await logActivity(db, {
      userId: user.id,
      action: 'model.pqc_signed',
      target: slug,
      details: `PQC signed with ${algorithm} by ${signer_did}`,
    });

    // -- Transparency log ---------------------------------------------------
    await appendLogEntry(db, {
      action: 'model:pqc_signed',
      actor_did: signer_did,
      target_type: 'model',
      target_id: slug,
      metadata: {
        algorithm,
        attestation_type,
        message_hash: message_hash || null,
        public_key_hex: public_key_hex
          ? `${public_key_hex.slice(0, 32)}...${public_key_hex.slice(-32)}`
          : null,
      },
    });

    return json(
      {
        ok: true,
        slug,
        version_id: versionId,
        algorithm,
        attestation_type,
        signed_at: now,
      },
      201,
    );
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
