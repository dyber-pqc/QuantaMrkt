import type { APIRoute } from 'astro';
import { getHndlLeaderboard } from '../../../lib/db';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const limit = parseInt(url.searchParams.get('limit') || '10', 10);
    const leaderboard = await getHndlLeaderboard(db, limit);

    return new Response(JSON.stringify(leaderboard), {
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
