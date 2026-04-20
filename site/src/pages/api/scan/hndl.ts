import type { APIRoute } from 'astro';
import { parseHfRepo, scanOrCache, runHndlScan } from '../../../lib/hndl-scanner';
import { checkRateLimit, getClientIp, rateLimitResponse } from '../../../lib/rate-limit';

/**
 * Public HNDL scan API — no auth required, rate-limited by IP.
 *
 * POST /api/scan/hndl
 * Body: { url: string, refresh?: boolean }
 *
 * GET /api/scan/hndl?repo=org/repo
 * GET /api/scan/hndl?url=https://huggingface.co/org/repo
 */

const COMMON_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Cache-Control': 'public, max-age=60',
};

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj, null, 2), { status, headers: COMMON_HEADERS });

export const OPTIONS: APIRoute = async () =>
  new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });

export const POST: APIRoute = async ({ request, locals }) => {
  const ip = getClientIp(request);
  if (!checkRateLimit(`hndl-scan:${ip}`, 30, 60_000)) {
    return rateLimitResponse();
  }

  try {
    const body = (await request.json().catch(() => ({}))) as any;
    const input: string = body.url || body.repo || '';
    const refresh: boolean = !!body.refresh;

    const repoId = parseHfRepo(input);
    if (!repoId) {
      return json(
        {
          error: 'Invalid input. Provide a HuggingFace URL (https://huggingface.co/org/repo) or a repo id (org/repo).',
        },
        400,
      );
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const result = refresh
      ? await runHndlScan(db, repoId)
      : await scanOrCache(db, repoId);

    return json({
      ok: true,
      scan: result,
      share_url: `https://quantamrkt.com/scan/hf/${repoId}`,
      badge_url_md: `![HNDL: ${result.risk_level}](https://quantamrkt.com/badge/hndl/${repoId}.svg)`,
      badge_url_svg: `https://quantamrkt.com/badge/hndl/${repoId}.svg`,
    });
  } catch (err: any) {
    const msg = err?.message || 'scan failed';
    const status = msg.toLowerCase().includes('404') ? 404 : 500;
    return json({ error: msg }, status);
  }
};

export const GET: APIRoute = async ({ url, request, locals }) => {
  const ip = getClientIp(request);
  if (!checkRateLimit(`hndl-scan:${ip}`, 60, 60_000)) {
    return rateLimitResponse();
  }

  try {
    const input = url.searchParams.get('url') || url.searchParams.get('repo') || '';
    const refresh = url.searchParams.get('refresh') === 'true';
    const repoId = parseHfRepo(input);
    if (!repoId) {
      return json({ error: 'Missing or invalid ?repo=org/repo or ?url=...' }, 400);
    }
    const db = (locals as any).runtime.env.DB as D1Database;
    const result = refresh ? await runHndlScan(db, repoId) : await scanOrCache(db, repoId);

    return json({
      ok: true,
      scan: result,
      share_url: `https://quantamrkt.com/scan/hf/${repoId}`,
      badge_url_md: `![HNDL: ${result.risk_level}](https://quantamrkt.com/badge/hndl/${repoId}.svg)`,
      badge_url_svg: `https://quantamrkt.com/badge/hndl/${repoId}.svg`,
    });
  } catch (err: any) {
    const msg = err?.message || 'scan failed';
    const status = msg.toLowerCase().includes('404') ? 404 : 500;
    return json({ error: msg }, status);
  }
};
