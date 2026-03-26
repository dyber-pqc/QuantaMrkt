import type { APIRoute } from 'astro';
import { getModels, createModel, logActivity } from '../../../lib/db';
import { getApiUser } from '../../../lib/api-auth';
import { appendLogEntry } from '../../../lib/transparency';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const q = url.searchParams.get('q') || undefined;
    const sort = url.searchParams.get('sort') || undefined;
    const risk = url.searchParams.get('risk') || undefined;
    const limit = parseInt(url.searchParams.get('limit') || '20', 10);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    const result = await getModels(db, { q, sort, risk, limit, offset });
    return new Response(JSON.stringify(result), {
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
    const { slug, name, author, description, tags, license, framework, parameters } = body;

    if (!slug || !name || !author) {
      return new Response(JSON.stringify({ error: 'Missing required fields: slug, name, author' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const model = await createModel(db, { slug, name, author, description, tags, license, framework, parameters });

    await logActivity(db, {
      userId: user.id,
      action: 'model.create',
      target: slug,
      details: `Created model ${name}`,
    });

    // Append to transparency log
    await appendLogEntry(db, {
      action: 'model:created',
      actor_did: undefined,
      target_type: 'model',
      target_id: slug,
      metadata: { name, author, framework: framework || null },
    });

    return new Response(JSON.stringify(model), {
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
