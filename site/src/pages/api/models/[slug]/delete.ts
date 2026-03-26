import type { APIRoute } from 'astro';
import { getApiUser } from '../../../../lib/api-auth';
import { logActivity } from '../../../../lib/db';
import { appendLogEntry } from '../../../../lib/transparency';

export const DELETE: APIRoute = async ({ params, request, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    const user = await getApiUser(locals, request);
    if (!user) {
      return json({ error: 'Unauthorized. Sign in to delete models.' }, 401);
    }

    const slug = params.slug;
    if (!slug) {
      return json({ error: 'Missing model slug.' }, 400);
    }

    const db = (locals as any).runtime?.env?.DB as D1Database;
    if (!db) {
      return json({ error: 'Database not available.' }, 500);
    }

    // Fetch the model
    const model = await db
      .prepare('SELECT id, slug, name, author FROM models WHERE slug = ?')
      .bind(slug)
      .first<{ id: number; slug: string; name: string; author: string }>();

    if (!model) {
      return json({ error: 'Model not found.' }, 404);
    }

    // Verify ownership: model author must match user login
    if (model.author !== user.login) {
      return json({ error: 'Forbidden. You can only delete your own models.' }, 403);
    }

    // Get version IDs for cascading deletes
    const versionsResult = await db
      .prepare('SELECT id FROM model_versions WHERE model_id = ?')
      .bind(model.id)
      .all<{ id: number }>();
    const versionIds = (versionsResult.results ?? []).map((v) => v.id);

    // Delete in order: signatures, files, versions, hndl, model
    if (versionIds.length > 0) {
      const placeholders = versionIds.map(() => '?').join(',');
      await db.batch([
        db.prepare(`DELETE FROM signatures WHERE version_id IN (${placeholders})`).bind(...versionIds),
        db.prepare(`DELETE FROM model_files WHERE version_id IN (${placeholders})`).bind(...versionIds),
      ]);
    }

    await db.batch([
      db.prepare('DELETE FROM model_versions WHERE model_id = ?').bind(model.id),
      db.prepare('DELETE FROM hndl_assessments WHERE model_id = ?').bind(model.id),
      db.prepare('DELETE FROM models WHERE id = ?').bind(model.id),
    ]);

    // Log activity
    await logActivity(db, {
      userId: user.id,
      action: 'model.delete',
      target: slug,
      details: `Deleted model ${model.name} (${slug})`,
    });

    // Append to transparency log
    await appendLogEntry(db, {
      action: 'model:deleted',
      actor_did: undefined,
      target_type: 'model',
      target_id: slug,
      metadata: {
        name: model.name,
        author: model.author,
        deleted_by: user.login,
      },
    });

    return json({ success: true, message: `Model ${slug} deleted.` });
  } catch (err: any) {
    console.error('Model delete error:', err);
    return json({ error: err.message || 'Internal server error' }, 500);
  }
};
