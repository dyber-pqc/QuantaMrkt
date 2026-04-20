import type { APIRoute } from 'astro';

/**
 * Public stats API — no auth required.
 * Returns live counts of everything on the registry for dashboards, badges, etc.
 */
export const GET: APIRoute = async ({ locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj, null, 2), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=60',
        'Access-Control-Allow-Origin': '*',
      },
    });

  try {
    const db = (locals as any).runtime.env.DB as D1Database;

    const queries = await Promise.all([
      db.prepare(`SELECT COUNT(*) as cnt FROM models WHERE category = 'model' OR category IS NULL`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM models WHERE category = 'dataset'`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM models WHERE category = 'tool'`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM agents`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM signatures WHERE attestation_type = 'pqc_registry'`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM signatures`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM chain_blocks`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM transparency_log`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM transparency_log WHERE timestamp > datetime('now', '-1 day')`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM hndl_assessments WHERE risk_level = 'CRITICAL'`).first<{ cnt: number }>(),
      db.prepare(`SELECT COUNT(*) as cnt FROM hndl_assessments WHERE risk_level = 'HIGH'`).first<{ cnt: number }>(),
      db.prepare(`SELECT SUM(size) as total FROM model_files`).first<{ total: number }>(),
      db.prepare(`SELECT timestamp FROM transparency_log ORDER BY id DESC LIMIT 1`).first<{ timestamp: string }>(),
      db.prepare(`SELECT timestamp FROM chain_blocks ORDER BY block_number DESC LIMIT 1`).first<{ timestamp: string }>(),
    ]);

    return json({
      registry: {
        models: queries[0]?.cnt ?? 0,
        datasets: queries[1]?.cnt ?? 0,
        tools: queries[2]?.cnt ?? 0,
        agents: queries[3]?.cnt ?? 0,
      },
      signatures: {
        pqc_signed: queries[4]?.cnt ?? 0,
        total: queries[5]?.cnt ?? 0,
        algorithm: 'ML-DSA-87',
        standard: 'FIPS 204',
      },
      blockchain: {
        blocks: queries[6]?.cnt ?? 0,
        transparency_entries: queries[7]?.cnt ?? 0,
        entries_last_24h: queries[8]?.cnt ?? 0,
        hash_algorithm: 'SHA-256',
      },
      hndl: {
        critical: queries[9]?.cnt ?? 0,
        high: queries[10]?.cnt ?? 0,
      },
      storage: {
        total_bytes_cataloged: queries[11]?.total ?? 0,
      },
      last_activity: {
        last_log_entry: queries[12]?.timestamp ?? null,
        last_block_minted: queries[13]?.timestamp ?? null,
      },
      generated_at: new Date().toISOString(),
      api_version: '1',
    });
  } catch (err: any) {
    return json({ error: err.message || 'Internal error' }, 500);
  }
};

// CORS preflight
export const OPTIONS: APIRoute = async () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
};
