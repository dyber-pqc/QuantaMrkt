import type { APIRoute } from 'astro';
import { getAgentByDid, getAgentById } from '../../../lib/db';

export const GET: APIRoute = async ({ params, locals }) => {
  try {
    const id = params.id;
    if (!id) {
      return new Response(JSON.stringify({ error: 'Missing id parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime.env.DB as D1Database;

    // Try numeric ID first, then DID
    let agent;
    const numericId = parseInt(id, 10);
    if (!isNaN(numericId) && String(numericId) === id) {
      agent = await getAgentById(db, numericId);
    } else {
      agent = await getAgentByDid(db, id);
    }

    if (!agent) {
      return new Response(JSON.stringify({ error: 'Agent not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify(agent), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
