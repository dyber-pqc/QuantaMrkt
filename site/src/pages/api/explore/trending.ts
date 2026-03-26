import type { APIRoute } from 'astro';
import { getTrendingModels } from '../../../lib/db';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const limit = parseInt(url.searchParams.get('limit') || '10', 10);
    const models = await getTrendingModels(db, limit);

    return new Response(JSON.stringify(models), {
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
