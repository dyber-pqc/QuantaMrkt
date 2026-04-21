import type { APIRoute } from 'astro';
import { getApiUser } from '../../../lib/api-auth';
import { getUserByGithubId } from '../../../lib/db';

/**
 * GET /api/watchlist/check?slug=...&kind=model
 * Returns { watched: boolean }. Used by the star button to init its state.
 */
export const GET: APIRoute = async ({ locals, request, url }) => {
  const user = await getApiUser(locals, request);
  if (!user) {
    return new Response(JSON.stringify({ watched: false, authenticated: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const db = (locals as any).runtime.env.DB as D1Database;
  const dbUser = await getUserByGithubId(db, (user as any).id ?? (user as any).github_id);
  if (!dbUser) {
    return new Response(JSON.stringify({ watched: false, authenticated: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const slug = url.searchParams.get('slug') || '';
  const kind = url.searchParams.get('kind') || 'model';
  const row = await db
    .prepare(`SELECT 1 FROM watchlist WHERE user_id = ? AND subject_kind = ? AND slug = ?`)
    .bind(dbUser.id, kind, slug)
    .first();

  return new Response(
    JSON.stringify({ watched: !!row, authenticated: true }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
};
