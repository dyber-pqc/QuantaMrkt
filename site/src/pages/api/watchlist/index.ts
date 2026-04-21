import type { APIRoute } from 'astro';
import { getApiUser } from '../../../lib/api-auth';
import { getUserByGithubId } from '../../../lib/db';

/**
 * User watchlist CRUD.
 *
 * GET  /api/watchlist              → list watched subjects (hydrated with risk)
 * POST /api/watchlist  {slug, kind?}→ add to watchlist
 * DELETE /api/watchlist?slug=...    → remove from watchlist
 */

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function resolveUser(locals: any, request: Request) {
  const user = await getApiUser(locals, request);
  if (!user) return null;
  const db = (locals as any).runtime.env.DB as D1Database;
  const dbUser = await getUserByGithubId(db, (user as any).id ?? (user as any).github_id);
  return dbUser ? { user: dbUser, db } : null;
}

export const GET: APIRoute = async ({ locals, request }) => {
  const ctx = await resolveUser(locals, request);
  if (!ctx) return json({ error: 'Unauthorized' }, 401);

  // Hydrate each watched slug with live metadata (risk, signatures, downloads).
  const rows = await ctx.db
    .prepare(
      `SELECT w.id as watch_id, w.subject_kind, w.slug, w.added_at, w.notify_email,
              m.name, m.author, m.description, m.downloads, m.verified, m.category,
              h.risk_level, h.risk_score, h.shelf_life_years,
              (SELECT COUNT(*) FROM signatures s
                 JOIN model_versions v ON s.version_id = v.id
                 WHERE v.model_id = m.id AND s.attestation_type = 'pqc_registry') as pqc_sig_count
         FROM watchlist w
         LEFT JOIN models m ON m.slug = w.slug
         LEFT JOIN hndl_assessments h ON h.model_id = m.id
         WHERE w.user_id = ?
         ORDER BY w.added_at DESC`,
    )
    .bind(ctx.user.id)
    .all<any>();

  return json({ items: rows.results || [] });
};

export const POST: APIRoute = async ({ locals, request }) => {
  const ctx = await resolveUser(locals, request);
  if (!ctx) return json({ error: 'Unauthorized' }, 401);

  const body = (await request.json().catch(() => ({}))) as any;
  const slug = String(body.slug || '').trim();
  const subjectKind = String(body.kind || 'model').trim();
  if (!slug) return json({ error: 'slug required' }, 400);

  try {
    await ctx.db
      .prepare(
        `INSERT INTO watchlist (user_id, subject_kind, slug, added_at, notify_email)
         VALUES (?, ?, ?, datetime('now'), 0)
         ON CONFLICT(user_id, subject_kind, slug) DO NOTHING`,
      )
      .bind(ctx.user.id, subjectKind, slug)
      .run();
    return json({ ok: true, slug, kind: subjectKind });
  } catch (e: any) {
    return json({ error: e?.message || 'failed' }, 500);
  }
};

export const DELETE: APIRoute = async ({ locals, request, url }) => {
  const ctx = await resolveUser(locals, request);
  if (!ctx) return json({ error: 'Unauthorized' }, 401);

  const slug = url.searchParams.get('slug') || '';
  const subjectKind = url.searchParams.get('kind') || 'model';
  if (!slug) return json({ error: 'slug required' }, 400);

  await ctx.db
    .prepare(`DELETE FROM watchlist WHERE user_id = ? AND subject_kind = ? AND slug = ?`)
    .bind(ctx.user.id, subjectKind, slug)
    .run();
  return json({ ok: true });
};
