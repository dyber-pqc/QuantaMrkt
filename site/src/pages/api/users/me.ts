import type { APIRoute } from 'astro';
import { getUserStats } from '../../../lib/db';
import { getApiUser } from '../../../lib/api-auth';

export const GET: APIRoute = async ({ request, locals }) => {
  try {
    const user = await getApiUser(locals, request);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const stats = await getUserStats(db, user.id);

    return new Response(
      JSON.stringify({
        user,
        stats,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
