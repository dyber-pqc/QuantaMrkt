import type { APIRoute } from 'astro';
import { getEntryWithProof } from '../../../../lib/transparency';

export const GET: APIRoute = async ({ params, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;

    const sequenceNumber = parseInt(params.id || '', 10);
    if (isNaN(sequenceNumber) || sequenceNumber < 1) {
      return new Response(
        JSON.stringify({ error: 'Invalid sequence number' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const result = await getEntryWithProof(db, sequenceNumber);

    if (!result) {
      return new Response(
        JSON.stringify({ error: 'Entry not found' }),
        { status: 404, headers: { 'Content-Type': 'application/json' } },
      );
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: err.message || 'Internal error' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } },
    );
  }
};
