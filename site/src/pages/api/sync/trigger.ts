import type { APIRoute } from 'astro';
import { getApiUser } from '../../../lib/api-auth';
import { syncHuggingFaceModels } from '../../../lib/hf-sync';
import { createBlock } from '../../../lib/pqc-chain';
import { checkRateLimit, getClientIp, rateLimitResponse } from '../../../lib/rate-limit';

export const POST: APIRoute = async ({ request, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  // Rate limit: 1 per minute
  const ip = getClientIp(request);
  if (!checkRateLimit(`sync:${ip}`, 1, 60_000)) {
    return rateLimitResponse();
  }

  try {
    // Require authentication (admin check: for now, any logged-in user)
    const user = await getApiUser(locals, request);
    if (!user) {
      return json({ error: 'Unauthorized. Sign in to trigger sync.' }, 401);
    }

    const db = (locals as any).runtime.env.DB as D1Database;

    // Run sync
    const result = await syncHuggingFaceModels(db, 30);

    // Create a new block from any new transparency log entries
    try {
      await createBlock(db);
    } catch {
      // Block creation is non-critical
    }

    return json({
      success: true,
      ...result,
    });
  } catch (err: any) {
    console.error('Sync trigger error:', err);
    return json({ error: err.message || 'Internal server error' }, 500);
  }
};
