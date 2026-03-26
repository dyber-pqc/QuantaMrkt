import type { APIRoute } from 'astro';
import { getRecentVerifications } from '../../../lib/db';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const limit = parseInt(url.searchParams.get('limit') || '10', 10);
    const verifications = await getRecentVerifications(db, limit);

    return new Response(JSON.stringify(verifications), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
