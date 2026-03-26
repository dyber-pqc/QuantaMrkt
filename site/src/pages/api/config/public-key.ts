import type { APIRoute } from 'astro';
import { getApiUser } from '../../../lib/api-auth';

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const user = await getApiUser(locals, request);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const body = (await request.json()) as { public_key_hex?: string };
    const pkHex = body.public_key_hex;

    if (!pkHex || pkHex.length < 100) {
      return new Response(JSON.stringify({ error: 'Invalid public key' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime?.env?.DB as D1Database;
    if (!db) {
      return new Response(JSON.stringify({ error: 'Database not available' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    await db
      .prepare(
        `INSERT INTO platform_config (key, value, updated_at) VALUES ('ml_dsa_87_public_key', ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
      )
      .bind(pkHex)
      .run();

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
