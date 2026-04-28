import type { APIRoute } from 'astro';

/**
 * Internal platform keypair store.
 *
 * GET  /api/internal/platform-keys   → { public_key_hex, private_key_hex }
 * POST /api/internal/platform-keys   { public_key_hex, private_key_hex }
 *
 * Cron-authenticated via X-Cron-Secret. Used by the pqc-sign workflow to
 * persist its ML-DSA-87 keypair across runs without requiring a GitHub PAT
 * with secrets:write scope.
 *
 * The keypair is stored in the platform_config table:
 *   - ml_dsa_87_public_key
 *   - ml_dsa_87_private_key
 *
 * Note: the private key sits in D1 behind CRON_SECRET — same trust boundary
 * as a GitHub Actions secret. Verifiers never need it; each signature already
 * embeds the public key it was signed with, so historical signatures remain
 * verifiable even after key rotation.
 */

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function authorized(request: Request, env: any): boolean {
  const provided = request.headers.get('x-cron-secret');
  return !!provided && !!env.CRON_SECRET && provided === env.CRON_SECRET;
}

export const GET: APIRoute = async ({ request, locals }) => {
  const env = (locals as any).runtime?.env;
  const db = env?.DB as D1Database | undefined;
  if (!db) return json({ error: 'Database not available' }, 500);
  if (!authorized(request, env)) {
    return json({ error: 'Unauthorized — valid X-Cron-Secret required' }, 401);
  }

  const rows = await db
    .prepare(
      `SELECT key, value FROM platform_config
        WHERE key IN ('ml_dsa_87_public_key', 'ml_dsa_87_private_key')`,
    )
    .all<{ key: string; value: string }>();

  const map = new Map<string, string>();
  for (const r of rows.results || []) map.set(r.key, r.value);

  return json({
    public_key_hex: map.get('ml_dsa_87_public_key') || null,
    private_key_hex: map.get('ml_dsa_87_private_key') || null,
  });
};

export const POST: APIRoute = async ({ request, locals }) => {
  const env = (locals as any).runtime?.env;
  const db = env?.DB as D1Database | undefined;
  if (!db) return json({ error: 'Database not available' }, 500);
  if (!authorized(request, env)) {
    return json({ error: 'Unauthorized — valid X-Cron-Secret required' }, 401);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const pkHex = String(body?.public_key_hex || '').trim();
  const skHex = String(body?.private_key_hex || '').trim();

  if (!pkHex || pkHex.length < 100) {
    return json({ error: 'public_key_hex required (hex string)' }, 400);
  }
  if (!skHex || skHex.length < 32) {
    return json({ error: 'private_key_hex required (hex string)' }, 400);
  }
  if (!/^[0-9a-fA-F]+$/.test(pkHex) || !/^[0-9a-fA-F]+$/.test(skHex)) {
    return json({ error: 'keys must be hex-encoded' }, 400);
  }

  await db.batch([
    db
      .prepare(
        `INSERT INTO platform_config (key, value, updated_at)
         VALUES ('ml_dsa_87_public_key', ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
      )
      .bind(pkHex),
    db
      .prepare(
        `INSERT INTO platform_config (key, value, updated_at)
         VALUES ('ml_dsa_87_private_key', ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
      )
      .bind(skHex),
  ]);

  return json({
    success: true,
    public_key_hex_length: pkHex.length,
    private_key_hex_length: skHex.length,
  });
};
