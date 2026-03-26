import type { APIRoute } from 'astro';
import { createGenesisBlock, createBlock } from '../../../lib/pqc-chain';
import { checkRateLimit, getClientIp, rateLimitResponse } from '../../../lib/rate-limit';

export const POST: APIRoute = async ({ request, locals }) => {
  // Rate limit: 1 per 10 minutes
  const ip = getClientIp(request);
  if (!checkRateLimit(`rebuild:${ip}`, 1, 600_000)) {
    return rateLimitResponse();
  }

  try {
    const db = (locals as any).runtime?.env?.DB;
    if (!db) {
      return new Response(JSON.stringify({ error: 'Database not available' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Clear existing blocks
    await db.prepare('DELETE FROM chain_blocks').run();

    // Create genesis block
    const genesis = await createGenesisBlock(db);

    // Keep creating blocks until no more pending entries
    const blocks = [genesis];
    let maxIterations = 50;
    while (maxIterations-- > 0) {
      const block = await createBlock(db);
      if (!block) break;
      blocks.push(block);
    }

    return new Response(
      JSON.stringify({
        success: true,
        blocks_created: blocks.length,
        latest_block: blocks[blocks.length - 1]?.block_number ?? 0,
        latest_hash: blocks[blocks.length - 1]?.block_hash ?? '',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: err.message || 'Failed to rebuild chain' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
};
