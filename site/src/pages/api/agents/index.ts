import type { APIRoute } from 'astro';
import { getAgents, createAgent, logActivity } from '../../../lib/db';
import { getApiUser } from '../../../lib/api-auth';
import { appendLogEntry } from '../../../lib/transparency';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const userIdParam = url.searchParams.get('user_id');
    const userId = userIdParam ? parseInt(userIdParam, 10) : undefined;

    const agents = await getAgents(db, { userId });
    return new Response(JSON.stringify(agents), {
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

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const user = await getApiUser(locals, request);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const body = await request.json() as Record<string, any>;
    const { name, did, algorithm, publicKeyHex, capabilities } = body;

    if (!name || !did || !algorithm) {
      return new Response(JSON.stringify({ error: 'Missing required fields: name, did, algorithm' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const agent = await createAgent(db, {
      userId: user.id,
      name,
      did,
      algorithm,
      publicKeyHex,
      capabilities,
    });

    await logActivity(db, {
      userId: user.id,
      action: 'agent.register',
      target: did,
      details: `Registered agent ${name}`,
    });

    // Append to transparency log
    await appendLogEntry(db, {
      action: 'agent:registered',
      actor_did: did,
      target_type: 'agent',
      target_id: did,
      metadata: { name, algorithm, capabilities: capabilities || [] },
    });

    return new Response(JSON.stringify(agent), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
