import type { APIRoute } from 'astro';
import { verifyBlockChain, getLatestBlock } from '../../../lib/pqc-chain';

export const GET: APIRoute = async ({ locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    const db = (locals as any).runtime.env.DB as D1Database;

    const verification = await verifyBlockChain(db);
    const latest = await getLatestBlock(db);

    return json({
      valid: verification.valid,
      blocks_checked: verification.blocks_checked,
      latest_block: latest ? {
        block_number: latest.block_number,
        block_hash: latest.block_hash,
        timestamp: latest.timestamp,
        entries_count: latest.entries_count,
      } : null,
      errors: verification.errors,
    });
  } catch (err: any) {
    return json({ error: err.message || 'Internal error' }, 500);
  }
};
