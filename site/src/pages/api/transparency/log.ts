import type { APIRoute } from 'astro';
import { getActivity } from '../../../lib/db';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);
    const activity = await getActivity(db, { limit });

    return new Response(JSON.stringify(activity), {
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
