import type { APIRoute } from 'astro';
import { getBlock, getBlockEntries } from '../../../../lib/pqc-chain';

export const GET: APIRoute = async ({ params, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const blockNumber = parseInt(params.number || '0', 10);

    const block = await getBlock(db, blockNumber);
    if (!block) {
      return json({ error: `Block ${blockNumber} not found` }, 404);
    }

    const entries = await getBlockEntries(db, blockNumber);

    return json({ block, entries });
  } catch (err: any) {
    return json({ error: err.message || 'Internal error' }, 500);
  }
};
