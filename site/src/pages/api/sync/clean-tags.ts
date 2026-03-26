import type { APIRoute } from 'astro';
import { processHfTags } from '../../../lib/hf-sync';

export const POST: APIRoute = async ({ locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    const db = (locals as any).runtime?.env?.DB as D1Database | undefined;
    if (!db) {
      return json({ error: 'Database not available' }, 500);
    }

    // Find all models with dirty tags (containing dataset:, arxiv:, license:, region:, etc.)
    const allModels = await db
      .prepare(
        `SELECT id, tags, category FROM models
         WHERE tags LIKE '%dataset:%'
            OR tags LIKE '%arxiv:%'
            OR tags LIKE '%license:%'
            OR tags LIKE '%region:%'
            OR tags LIKE '%endpoints_compatible%'
            OR tags LIKE '%deploy:%'
            OR tags LIKE '%text-embeddings-inference%'`,
      )
      .all<{ id: number; tags: string | null; category: string | null }>();

    const rows = allModels.results ?? [];
    let cleaned = 0;
    const errors: string[] = [];

    for (const row of rows) {
      try {
        const rawTags: string[] = row.tags ? JSON.parse(row.tags) : [];
        if (rawTags.length === 0) continue;

        // The pipeline_tag is stored in the category column
        const pipelineTag = row.category || null;
        const cleanedTags = processHfTags(rawTags, pipelineTag);

        await db
          .prepare('UPDATE models SET tags = ? WHERE id = ?')
          .bind(JSON.stringify(cleanedTags), row.id)
          .run();

        cleaned++;
      } catch (err: any) {
        errors.push(`Model ${row.id}: ${err.message}`);
      }
    }

    return json({
      success: true,
      total_found: rows.length,
      cleaned,
      errors,
    });
  } catch (err: any) {
    console.error('Clean tags error:', err);
    return json({ error: err.message || 'Internal server error' }, 500);
  }
};
