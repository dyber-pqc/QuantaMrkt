import type { APIRoute } from 'astro';
import { verifyChain, getLatestEntry } from '../../../lib/transparency';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;

    const fromParam = url.searchParams.get('from');
    const toParam = url.searchParams.get('to');

    const fromSeq = fromParam ? parseInt(fromParam, 10) : undefined;
    const toSeq = toParam ? parseInt(toParam, 10) : undefined;

    const result = await verifyChain(db, fromSeq, toSeq);
    const latest = await getLatestEntry(db);

    return new Response(
      JSON.stringify({
        valid: result.valid,
        entries_checked: result.entries_checked,
        latest_sequence: latest?.sequence_number ?? 0,
        latest_hash: latest?.payload_hash ?? null,
        first_invalid: result.first_invalid ?? null,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: err.message || 'Internal error' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } },
    );
  }
};
