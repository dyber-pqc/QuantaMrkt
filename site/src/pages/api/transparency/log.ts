import type { APIRoute } from 'astro';
import { getLogEntries, verifyChain } from '../../../lib/transparency';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;

    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);
    const action = url.searchParams.get('action') || undefined;
    const targetType = url.searchParams.get('target_type') || undefined;
    const targetId = url.searchParams.get('target') || url.searchParams.get('target_id') || undefined;

    const { entries, total } = await getLogEntries(db, {
      limit,
      offset,
      action,
      target_type: targetType,
      target_id: targetId,
    });

    // Quick chain validation on the returned entries (verify latest 10 for speed)
    const latestSeq = entries.length > 0 ? entries[0].sequence_number : 0;
    const fromSeq = Math.max(1, latestSeq - 9);
    const chainResult = latestSeq > 0
      ? await verifyChain(db, fromSeq, latestSeq)
      : { valid: true };

    return new Response(
      JSON.stringify({
        entries,
        total,
        chain_valid: chainResult.valid,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: err.message || 'Internal error' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  }
};
