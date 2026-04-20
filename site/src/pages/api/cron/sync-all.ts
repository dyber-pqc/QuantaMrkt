import type { APIRoute } from 'astro';
import { syncHuggingFaceModels, syncHuggingFaceDatasets } from '../../../lib/hf-sync';
import { createBlock } from '../../../lib/pqc-chain';
import { appendLogEntry } from '../../../lib/transparency';

/**
 * Scheduled sync endpoint — triggered hourly by GitHub Actions cron.
 * Requires X-Cron-Secret header matching CRON_SECRET env var.
 *
 * Performs:
 *  1. HuggingFace model sync (top N per category)
 *  2. HuggingFace dataset sync
 *  3. Auto-mint new transparency block if enough new entries
 *  4. Log the cron run to transparency log
 */
export const POST: APIRoute = async ({ request, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj, null, 2), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

  try {
    const env = (locals as any).runtime.env;
    const db = env.DB as D1Database;
    const expectedSecret = env.CRON_SECRET;

    // Verify cron secret
    const providedSecret = request.headers.get('x-cron-secret');
    if (!expectedSecret || providedSecret !== expectedSecret) {
      return json({ error: 'Unauthorized' }, 401);
    }

    const started = Date.now();
    const results: any = {
      started_at: new Date(started).toISOString(),
      models: null,
      datasets: null,
      block: null,
      duration_ms: 0,
    };

    // 1. Sync models
    try {
      results.models = await syncHuggingFaceModels(db, 50);
    } catch (err: any) {
      results.models = { error: err.message };
    }

    // 2. Sync datasets
    try {
      results.datasets = await syncHuggingFaceDatasets(db, 25);
    } catch (err: any) {
      results.datasets = { error: err.message };
    }

    // 3. Auto-mint block if enough new entries
    try {
      const pendingEntries = await db
        .prepare(
          `SELECT COUNT(*) as cnt FROM transparency_log
           WHERE id > COALESCE((SELECT MAX(end_entry_id) FROM chain_blocks), 0)`,
        )
        .first<{ cnt: number }>();

      if (pendingEntries && pendingEntries.cnt >= 5) {
        const block = await createBlock(db);
        results.block = {
          minted: true,
          block_number: block?.block_number,
          entry_count: block?.entry_count,
        };
      } else {
        results.block = {
          minted: false,
          pending_entries: pendingEntries?.cnt || 0,
          reason: 'Not enough pending entries (need 5+)',
        };
      }
    } catch (err: any) {
      results.block = { error: err.message };
    }

    results.duration_ms = Date.now() - started;

    // Log the cron run itself
    await appendLogEntry(db, {
      action: 'cron:sync-completed',
      actor_did: 'did:quantamrkt:cron:hourly-sync',
      target_type: 'system',
      target_id: 'hf-sync',
      metadata: {
        models_created: results.models?.created ?? 0,
        models_updated: results.models?.updated ?? 0,
        datasets_created: results.datasets?.created ?? 0,
        datasets_updated: results.datasets?.updated ?? 0,
        duration_ms: results.duration_ms,
        block_minted: results.block?.minted ?? false,
      },
    });

    return json({ success: true, ...results });
  } catch (err: any) {
    return json({ error: err.message || 'Internal server error' }, 500);
  }
};

// Also accept GET for easier testing/cron services that only support GET
export const GET: APIRoute = async (ctx) => POST(ctx);
