import type { APIRoute } from 'astro';

/**
 * Public verification API — no auth required.
 * GET /api/v1/verify/:slug returns full PQC verification details.
 * Includes platform public key so clients can verify signatures locally.
 */
export const GET: APIRoute = async ({ params, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj, null, 2), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=30',
        'Access-Control-Allow-Origin': '*',
      },
    });

  try {
    const slug = params.slug;
    if (!slug) return json({ error: 'slug required' }, 400);

    const env = (locals as any).runtime.env;
    const db = env.DB as D1Database;

    // Fetch model + latest version + files + signatures
    const model = await db
      .prepare(`SELECT * FROM models WHERE slug = ?`)
      .bind(slug)
      .first<any>();

    if (!model) {
      return json({ error: 'Model not found', slug }, 404);
    }

    const version = await db
      .prepare(`SELECT * FROM model_versions WHERE model_id = ? ORDER BY id DESC LIMIT 1`)
      .bind(model.id)
      .first<any>();

    if (!version) {
      return json({
        slug,
        name: model.name,
        verification: { status: 'no_version' },
        error: 'No version found for model',
      }, 404);
    }

    const files = await db
      .prepare(`SELECT filename, sha3_256_hash, size FROM model_files WHERE version_id = ?`)
      .bind(version.id)
      .all<any>();

    const signatures = await db
      .prepare(`SELECT signer_did, algorithm, signature_hex, attestation_type, signed_at,
                public_key_hex, message_hash FROM signatures WHERE version_id = ? ORDER BY signed_at`)
      .bind(version.id)
      .all<any>();

    // Fetch platform public key
    const pkRow = await db
      .prepare(`SELECT value FROM platform_config WHERE key = 'ml_dsa_87_public_key'`)
      .first<{ value: string }>();
    const platformPublicKey = pkRow?.value || env.PLATFORM_ML_DSA_PUBLIC_KEY || null;

    // Get HNDL assessment
    const hndl = await db
      .prepare(`SELECT * FROM hndl_assessments WHERE model_id = ? ORDER BY id DESC LIMIT 1`)
      .bind(model.id)
      .first<any>();

    // Get transparency log entries for this model
    const logEntries = await db
      .prepare(`SELECT sequence_number, action, timestamp, payload_hash
                FROM transparency_log
                WHERE target_type IN ('model', 'dataset') AND target_id = ?
                ORDER BY id DESC LIMIT 20`)
      .bind(slug)
      .all<any>();

    // Classify signatures
    const pqcSigs = (signatures.results || []).filter((s: any) => s.attestation_type === 'pqc_registry');
    const classicalSigs = (signatures.results || []).filter((s: any) => s.attestation_type !== 'pqc_registry');

    const verificationStatus = pqcSigs.length > 0
      ? 'pqc_verified'
      : classicalSigs.length > 0
        ? 'classical_only'
        : 'unsigned';

    return json({
      slug,
      name: model.name,
      author: model.author,
      category: model.category || 'model',
      source: {
        platform: model.source_platform,
        url: model.source_url,
        hf_repo_id: model.hf_repo_id,
      },
      version: {
        id: version.id,
        label: version.version,
        manifest_hash: version.manifest_hash,
        file_count: version.file_count,
        total_size: version.total_size,
      },
      verification: {
        status: verificationStatus,
        pqc_signatures: pqcSigs.length,
        total_signatures: signatures.results?.length || 0,
        platform_public_key_hex: platformPublicKey,
        signing_algorithm: 'ML-DSA-87',
        signing_standard: 'FIPS 204',
        hash_algorithm: 'SHA3-256',
        verify_locally_with: 'pip install quantumshield',
      },
      signatures: (signatures.results || []).map((s: any) => ({
        signer_did: s.signer_did,
        algorithm: s.algorithm,
        attestation_type: s.attestation_type,
        signature_hex: s.signature_hex,
        message_hash: s.message_hash || null,
        public_key_hex: s.public_key_hex || null,
        signed_at: s.signed_at,
      })),
      files: (files.results || []).map((f: any) => ({
        filename: f.filename,
        sha3_256: f.sha3_256_hash,
        size: f.size,
      })),
      hndl_assessment: hndl ? {
        risk_level: hndl.risk_level,
        risk_score: hndl.risk_score,
        shelf_life_years: hndl.shelf_life_years,
        recommendation: hndl.recommendation,
      } : null,
      transparency_log: (logEntries.results || []).map((e: any) => ({
        seq: e.sequence_number,
        action: e.action,
        timestamp: e.timestamp,
        hash: e.payload_hash,
      })),
      api_version: '1',
      verified_at: new Date().toISOString(),
    });
  } catch (err: any) {
    return json({ error: err.message || 'Internal error' }, 500);
  }
};

export const OPTIONS: APIRoute = async () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
};
