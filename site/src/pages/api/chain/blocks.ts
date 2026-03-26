import type { APIRoute } from 'astro';
import { getBlocks } from '../../../lib/pqc-chain';

export const GET: APIRoute = async ({ url, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 100);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    const { blocks, total } = await getBlocks(db, { limit, offset });

    return json({ blocks, total });
  } catch (err: any) {
    return json({ error: err.message || 'Internal error' }, 500);
  }
};
