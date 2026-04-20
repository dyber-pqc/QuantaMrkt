import type { APIRoute } from 'astro';
import { parseHfRepo, scanOrCache } from '../../../../lib/hndl-scanner';

/**
 * GET /og/scan/hf/{org}/{repo}.svg
 *
 * 1200x630 social-card SVG for an HNDL scan result.
 * Works natively as og:image on most platforms. Served cached for 10 minutes.
 */

const RISK: Record<string, { fill: string; label: string }> = {
  CRITICAL: { fill: '#ef4444', label: 'CRITICAL' },
  HIGH:     { fill: '#f97316', label: 'HIGH' },
  MEDIUM:   { fill: '#eab308', label: 'MEDIUM' },
  LOW:      { fill: '#22c55e', label: 'LOW' },
};

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

function renderCard(opts: {
  repo: string;
  risk_level: string;
  risk_score: number;
  shelf_life: number;
  recommendation: string;
  downloads: number;
  pipeline: string | null;
}): string {
  const risk = RISK[opts.risk_level] ?? RISK.MEDIUM;
  const recShort = truncate(opts.recommendation, 110);
  const pipeline = opts.pipeline || 'unknown';
  const dlShort = opts.downloads >= 1_000_000
    ? (opts.downloads / 1_000_000).toFixed(1) + 'M'
    : opts.downloads >= 1000
      ? (opts.downloads / 1000).toFixed(0) + 'K'
      : String(opts.downloads);

  // Ring math: circumference of r=100 is ~628
  const r = 100;
  const circ = 2 * Math.PI * r;
  const fillFrac = Math.min(1, opts.risk_score / 100);
  const offset = circ * (1 - fillFrac);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0a0f1e"/>
      <stop offset="100%" stop-color="#12182b"/>
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#00d4ff"/>
      <stop offset="100%" stop-color="#8b5cf6"/>
    </linearGradient>
  </defs>

  <rect width="1200" height="630" fill="url(#bg)"/>

  <g fill="#00d4ff">
    <rect x="60" y="60" width="40" height="40" rx="10" fill="#00d4ff" fill-opacity="0.15"/>
    <text x="80" y="88" font-family="Inter, Verdana, sans-serif" font-size="22" font-weight="800" text-anchor="middle" fill="#00d4ff">Q</text>
  </g>
  <text x="110" y="88" font-family="Inter, Verdana, sans-serif" font-size="22" font-weight="700" fill="#ffffff">QuantaMrkt</text>
  <text x="1140" y="88" font-family="Inter, Verdana, sans-serif" font-size="18" fill="#7c849c" text-anchor="end">HNDL Risk Scanner</text>

  <text x="60" y="160" font-family="Inter, Verdana, sans-serif" font-size="22" font-weight="500" fill="#7c849c">huggingface.co/</text>
  <text x="60" y="210" font-family="Inter, Verdana, sans-serif" font-size="42" font-weight="800" fill="#ffffff">${escapeXml(truncate(opts.repo, 38))}</text>

  <g transform="translate(60, 280)">
    <rect width="260" height="36" rx="18" fill="${risk.fill}" fill-opacity="0.15" stroke="${risk.fill}" stroke-width="2"/>
    <text x="130" y="24" font-family="Inter, Verdana, sans-serif" font-size="18" font-weight="700" text-anchor="middle" fill="${risk.fill}" letter-spacing="2">${risk.label} HNDL RISK</text>
  </g>

  <g transform="translate(60, 360)">
    <text font-family="Inter, Verdana, sans-serif" font-size="16" fill="#7c849c" text-transform="uppercase">Shelf Life</text>
    <text y="42" font-family="Inter, Verdana, sans-serif" font-size="36" font-weight="700" fill="#ffffff">~${opts.shelf_life} years</text>
  </g>

  <g transform="translate(340, 360)">
    <text font-family="Inter, Verdana, sans-serif" font-size="16" fill="#7c849c" text-transform="uppercase">Downloads</text>
    <text y="42" font-family="Inter, Verdana, sans-serif" font-size="36" font-weight="700" fill="#ffffff">${escapeXml(dlShort)}</text>
  </g>

  <g transform="translate(560, 360)">
    <text font-family="Inter, Verdana, sans-serif" font-size="16" fill="#7c849c" text-transform="uppercase">Type</text>
    <text y="42" font-family="Inter, Verdana, sans-serif" font-size="24" font-weight="600" fill="#ffffff">${escapeXml(truncate(pipeline, 18))}</text>
  </g>

  <text x="60" y="510" font-family="Inter, Verdana, sans-serif" font-size="20" fill="#d1d5db" font-weight="400">
    <tspan x="60" dy="0">${escapeXml(recShort)}</tspan>
  </text>

  <rect x="60" y="550" width="1080" height="1" fill="#1f2937"/>
  <text x="60" y="585" font-family="Inter, Verdana, sans-serif" font-size="16" fill="#7c849c">Scan any HuggingFace model — free, no login — at quantamrkt.com/scan</text>
  <text x="1140" y="585" font-family="Inter, Verdana, sans-serif" font-size="16" fill="#00d4ff" text-anchor="end" font-weight="600">PQC-native</text>

  <g transform="translate(920, 150)">
    <circle cx="0" cy="0" r="${r}" fill="none" stroke="#1f2937" stroke-width="14"/>
    <circle cx="0" cy="0" r="${r}" fill="none" stroke="${risk.fill}" stroke-width="14"
            stroke-linecap="round" stroke-dasharray="${circ}"
            stroke-dashoffset="${offset.toFixed(2)}"
            transform="rotate(-90)"/>
    <text y="-4" font-family="Inter, Verdana, sans-serif" font-size="56" font-weight="800" text-anchor="middle" fill="#ffffff">${opts.risk_score}</text>
    <text y="34" font-family="Inter, Verdana, sans-serif" font-size="16" text-anchor="middle" fill="#7c849c">of 100</text>
  </g>
</svg>`;
}

function headers(seconds: number) {
  return {
    'Content-Type': 'image/svg+xml; charset=utf-8',
    'Cache-Control': `public, max-age=${seconds}, s-maxage=${seconds}`,
    'Access-Control-Allow-Origin': '*',
  };
}

export const GET: APIRoute = async ({ params, locals }) => {
  const raw = String(params.path || '').replace(/\.svg$/, '');
  const repoId = parseHfRepo(raw);
  if (!repoId) {
    return new Response('Invalid path', { status: 400 });
  }
  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const scan = await scanOrCache(db, repoId);
    const svg = renderCard({
      repo: scan.hf_repo_id,
      risk_level: scan.risk_level,
      risk_score: scan.risk_score,
      shelf_life: scan.shelf_life_years,
      recommendation: scan.recommendation,
      downloads: scan.downloads,
      pipeline: scan.pipeline_tag,
    });
    return new Response(svg, { status: 200, headers: headers(600) });
  } catch {
    // Simple fallback card
    const svg = renderCard({
      repo: repoId,
      risk_level: 'MEDIUM',
      risk_score: 50,
      shelf_life: 7,
      recommendation: 'Scan data unavailable — visit the page to trigger a fresh scan.',
      downloads: 0,
      pipeline: null,
    });
    return new Response(svg, { status: 200, headers: headers(60) });
  }
};
