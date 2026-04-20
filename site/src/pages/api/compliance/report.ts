import type { APIRoute } from 'astro';
import { generateComplianceReportPdf } from '../../../lib/compliance-report';
import { scanOrCache } from '../../../lib/hndl-scanner';
import { checkRateLimit, getClientIp, rateLimitResponse } from '../../../lib/rate-limit';
import { getApiUser } from '../../../lib/api-auth';

/**
 * Generate a compliance report PDF for a model/dataset/tool.
 *
 * GET  /api/compliance/report?slug=<slug>  → returns application/pdf
 * GET  /api/compliance/report?repo=<org/repo> → derives slug, scans if needed
 * POST /api/compliance/report
 *      body: { slug?: string, repo?: string, tier?: 'free'|'pro' }
 *
 * Free tier: watermarked, no auth required (rate-limited by IP)
 * Pro tier: requires login + upgrade check (stubbed — always returns free if not upgraded)
 */

function err(msg: string, status = 400) {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function buildReport(
  db: D1Database,
  locals: any,
  opts: { slug?: string; repo?: string; tier?: 'free' | 'pro'; generatedBy?: string | null },
): Promise<Response> {
  let slug = (opts.slug || '').trim();
  let hf_repo_id: string | null = null;
  let subject: any = null;

  // 1. Look up subject — by slug first, then by hf_repo_id (scan into DB if needed)
  if (slug) {
    subject = await db.prepare(`SELECT * FROM models WHERE slug = ?`).bind(slug).first<any>();
    if (subject) hf_repo_id = subject.hf_repo_id || null;
  } else if (opts.repo) {
    hf_repo_id = opts.repo.trim();
    subject = await db.prepare(`SELECT * FROM models WHERE hf_repo_id = ?`).bind(hf_repo_id).first<any>();
    if (subject) slug = subject.slug;
  }

  // 2. If no registered subject, fall back to using the HF repo directly
  //    (still generates a valid report, just without platform signatures)
  let signatures: any[] = [];
  let transparency: any[] = [];
  let hndlRow: any = null;
  let latestVersion: any = null;

  if (subject) {
    latestVersion = await db
      .prepare(`SELECT * FROM model_versions WHERE model_id = ? ORDER BY id DESC LIMIT 1`)
      .bind(subject.id)
      .first<any>();
    if (latestVersion) {
      const sigRows = await db
        .prepare(`SELECT signer_did, algorithm, attestation_type, signature_hex, signed_at
                  FROM signatures WHERE version_id = ? ORDER BY signed_at`)
        .bind(latestVersion.id)
        .all<any>();
      signatures = sigRows.results || [];
    }
    hndlRow = await db
      .prepare(`SELECT * FROM hndl_assessments WHERE model_id = ? ORDER BY id DESC LIMIT 1`)
      .bind(subject.id)
      .first<any>();
    const logRows = await db
      .prepare(`SELECT sequence_number, action, timestamp, payload_hash
                FROM transparency_log
                WHERE target_id = ?
                ORDER BY id DESC LIMIT 30`)
      .bind(subject.slug)
      .all<any>();
    transparency = logRows.results || [];
  }

  // 3. HNDL — prefer fresh scan from hndl_scans, else on-the-fly
  let hndl = null;
  if (hf_repo_id) {
    try {
      hndl = await scanOrCache(db, hf_repo_id);
    } catch {
      // Continue without HNDL
    }
  }
  if (!hndl && hndlRow) {
    // Convert legacy hndl_assessments row into the shape buildHndlPage expects
    hndl = {
      hf_repo_id: hf_repo_id || slug,
      model_name: subject?.name || slug,
      author: subject?.author || '',
      risk_level: hndlRow.risk_level,
      risk_score: hndlRow.risk_score,
      shelf_life_years: hndlRow.shelf_life_years,
      recommendation: hndlRow.recommendation || '',
      downloads: subject?.downloads || 0,
      likes: subject?.likes || 0,
      pipeline_tag: subject?.framework || null,
      license: subject?.license || null,
      total_size: latestVersion?.total_size || 0,
      file_count: latestVersion?.file_count || 0,
      breakdown: [
        {
          factor: 'Legacy assessment',
          points: hndlRow.risk_score || 0,
          reason: 'Risk score derived from registry-side assessment; re-run scanner for detailed breakdown.',
        },
      ],
      scanned_at: hndlRow.assessed_at || '',
      fresh: false,
      scan_count: 1,
    };
  }

  // 4. Determine final subject metadata (use DB if registered, HF-derived otherwise)
  let finalSubject: any;
  if (subject) {
    finalSubject = {
      kind: (subject.category as 'model' | 'dataset' | 'tool') || 'model',
      slug: subject.slug,
      name: subject.name,
      author: subject.author,
      description: subject.description,
      source_platform: subject.source_platform,
      source_url: subject.source_url,
      hf_repo_id: subject.hf_repo_id,
    };
  } else if (hf_repo_id && hndl) {
    finalSubject = {
      kind: 'model' as const,
      slug: hf_repo_id.replace(/\//g, '--').toLowerCase(),
      name: hndl.model_name,
      author: hndl.author,
      description: null,
      source_platform: 'huggingface',
      source_url: `https://huggingface.co/${hf_repo_id}`,
      hf_repo_id,
    };
  } else {
    return err(
      'Could not locate subject. Provide either an existing QuantaMrkt slug via ?slug= or a HuggingFace repo via ?repo=org/repo.',
      404,
    );
  }

  // 5. Build report
  const tier = opts.tier || 'free';
  const reportId = `urn:pqc-compliance:${crypto.randomUUID()}`;
  const generatedAt = new Date().toISOString();

  const pdfBytes = await generateComplianceReportPdf({
    subject: finalSubject,
    hndl,
    signatures,
    transparency,
    generated_by: opts.generatedBy || null,
    generated_at: generatedAt,
    report_id: reportId,
    tier,
  });

  const filename = `compliance-${finalSubject.slug}-${Date.now()}.pdf`;
  return new Response(pdfBytes, {
    status: 200,
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `inline; filename="${filename}"`,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'X-Report-Id': reportId,
      'X-Report-Tier': tier,
    },
  });
}

export const GET: APIRoute = async ({ url, request, locals }) => {
  const ip = getClientIp(request);
  if (!checkRateLimit(`compliance:${ip}`, 20, 60_000)) {
    return rateLimitResponse();
  }
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const user = await getApiUser(locals, request);
    const requestedTier = url.searchParams.get('tier') as 'free' | 'pro' | null;
    const tier: 'free' | 'pro' = requestedTier === 'pro' && user ? 'free' : 'free'; // pro gated: always free for now

    return await buildReport(db, locals, {
      slug: url.searchParams.get('slug') || '',
      repo: url.searchParams.get('repo') || '',
      tier,
      generatedBy: user?.login || null,
    });
  } catch (e: any) {
    return err(e?.message || 'Internal error', 500);
  }
};

export const POST: APIRoute = async ({ request, locals }) => {
  const ip = getClientIp(request);
  if (!checkRateLimit(`compliance:${ip}`, 20, 60_000)) {
    return rateLimitResponse();
  }
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const body = (await request.json().catch(() => ({}))) as any;
    const user = await getApiUser(locals, request);
    const requestedTier = (body.tier as 'free' | 'pro') || 'free';
    const tier: 'free' | 'pro' = requestedTier === 'pro' && user ? 'free' : 'free';

    return await buildReport(db, locals, {
      slug: body.slug || '',
      repo: body.repo || '',
      tier,
      generatedBy: user?.login || null,
    });
  } catch (e: any) {
    return err(e?.message || 'Internal error', 500);
  }
};
