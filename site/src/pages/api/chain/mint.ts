import type { APIRoute } from 'astro';
import { getApiUser } from '../../../lib/api-auth';
import { createBlock } from '../../../lib/pqc-chain';
import { checkRateLimit, getClientIp, rateLimitResponse } from '../../../lib/rate-limit';

export const POST: APIRoute = async ({ request, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  // Rate limit: 5 per minute
  const ip = getClientIp(request);
  if (!checkRateLimit(`mint:${ip}`, 5, 60_000)) {
    return rateLimitResponse();
  }

  try {
    // Require authentication
    const user = await getApiUser(locals, request);
    if (!user) {
      return json({ error: 'Unauthorized. Sign in to mint blocks.' }, 401);
    }

    const db = (locals as any).runtime.env.DB as D1Database;

    const block = await createBlock(db);

    if (!block) {
      return json({ message: 'No pending entries to include in a new block.' });
    }

    return json({
      success: true,
      block: {
        block_number: block.block_number,
        block_hash: block.block_hash,
        merkle_root: block.merkle_root,
        entries_count: block.entries_count,
        entry_range: [block.entry_range_start, block.entry_range_end],
        timestamp: block.timestamp,
        signature: block.signature,
        signer_did: block.signer_did,
      },
    });
  } catch (err: any) {
    console.error('Block mint error:', err);
    return json({ error: err.message || 'Internal server error' }, 500);
  }
};
