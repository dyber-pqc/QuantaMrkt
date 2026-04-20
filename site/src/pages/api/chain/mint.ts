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
    const env = (locals as any).runtime.env;
    const db = env.DB as D1Database;

    // Allow either: logged-in user OR valid cron secret (for automated signing)
    const cronSecret = request.headers.get('x-cron-secret');
    const isAuthorizedCron = cronSecret && env.CRON_SECRET && cronSecret === env.CRON_SECRET;

    if (!isAuthorizedCron) {
      const user = await getApiUser(locals, request);
      if (!user) {
        return json({ error: 'Unauthorized. Sign in or provide valid cron secret.' }, 401);
      }
    }

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
