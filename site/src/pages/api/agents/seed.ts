import type { APIRoute } from 'astro';
import { appendLogEntry } from '../../../lib/transparency';

/**
 * POST /api/agents/seed
 *
 * Registers a real (ML-DSA keypair + platform-signed) agent identity.
 * Invoked only by the seed-agents GitHub Action using X-Cron-Secret.
 *
 * Body: {
 *   name, did, algorithm, public_key_hex, capabilities[], status,
 *   source_url, platform_signer_did, platform_signature
 * }
 *
 * If an agent with this name already exists, it's updated (replacing any
 * placeholder DID). Otherwise a new row is inserted with user_id=null
 * (owned by the platform).
 */

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const POST: APIRoute = async ({ request, locals }) => {
  const env = (locals as any).runtime.env;
  const db = env.DB as D1Database;

  // Cron-secret gate (only the seed workflow can call this)
  const provided = request.headers.get('x-cron-secret');
  if (!provided || !env.CRON_SECRET || provided !== env.CRON_SECRET) {
    return json({ error: 'Unauthorized — valid X-Cron-Secret required' }, 401);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const {
    name,
    did,
    algorithm,
    public_key_hex,
    capabilities,
    status,
    source_url,
    platform_signer_did,
    platform_signature,
  } = body || {};

  if (!name || !did || !algorithm || !public_key_hex) {
    return json(
      { error: 'Missing required fields: name, did, algorithm, public_key_hex' },
      400,
    );
  }

  try {
    // Ensure the agents table has a source_url column (safe to run repeatedly)
    try {
      await db.prepare(`ALTER TABLE agents ADD COLUMN source_url TEXT`).run();
    } catch {
      // column already exists — ignore
    }
    try {
      await db.prepare(`ALTER TABLE agents ADD COLUMN platform_signer_did TEXT`).run();
    } catch { /* ignore */ }
    try {
      await db.prepare(`ALTER TABLE agents ADD COLUMN platform_signature TEXT`).run();
    } catch { /* ignore */ }

    // Upsert by name (the canonical identifier in our registry)
    const existing = await db
      .prepare(`SELECT id FROM agents WHERE name = ?`)
      .bind(name)
      .first<{ id: number }>();

    const capsJson = JSON.stringify(Array.isArray(capabilities) ? capabilities : []);
    const safeStatus = String(status || 'active');

    if (existing) {
      await db
        .prepare(
          `UPDATE agents
             SET did = ?, algorithm = ?, public_key_hex = ?, capabilities_json = ?,
                 status = ?, source_url = ?, platform_signer_did = ?, platform_signature = ?
           WHERE id = ?`,
        )
        .bind(
          did, algorithm, public_key_hex, capsJson,
          safeStatus, source_url || null, platform_signer_did || null,
          platform_signature || null, existing.id,
        )
        .run();
    } else {
      await db
        .prepare(
          `INSERT INTO agents (
             user_id, name, did, algorithm, public_key_hex, capabilities_json,
             status, source_url, platform_signer_did, platform_signature, created_at
           ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        )
        .bind(
          name, did, algorithm, public_key_hex, capsJson,
          safeStatus, source_url || null, platform_signer_did || null,
          platform_signature || null,
        )
        .run();
    }

    // Transparency log entry — this agent has been platform-registered
    await appendLogEntry(db, {
      action: 'agent:platform-registered',
      actor_did: did,
      target_type: 'agent',
      target_id: did,
      metadata: {
        name,
        algorithm,
        capabilities: Array.isArray(capabilities) ? capabilities : [],
        source_url: source_url || null,
        signed_by: platform_signer_did || null,
      },
    });

    return json({ ok: true, name, did });
  } catch (err: any) {
    return json({ error: err?.message || 'Internal error' }, 500);
  }
};
