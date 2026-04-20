import type { APIRoute } from 'astro';
import { parseHfRepo, scanOrCache } from '../../../lib/hndl-scanner';

/**
 * GET /badge/hndl/{org}/{repo}.svg
 *
 * Shields.io-style SVG badge showing HNDL risk for a HuggingFace model.
 * Safe to embed in GitHub READMEs, blog posts, LinkedIn, etc.
 */

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  UNKNOWN: '#6b7280',
};

const PILL_LEFT_TEXT = 'HNDL';
const PILL_LEFT_COLOR = '#374151';
const PILL_TEXT_COLOR = '#ffffff';

function estimateTextWidth(text: string, fontSize = 11): number {
  // Approximate width of DejaVu Sans / Verdana-style rendering at the given size.
  // Conservative — we slightly over-estimate to avoid clipped text.
  let w = 0;
  for (const ch of text) {
    if (/[A-Z0-9]/.test(ch)) w += fontSize * 0.66;
    else if (/[a-z]/.test(ch)) w += fontSize * 0.56;
    else if (ch === ' ') w += fontSize * 0.32;
    else w += fontSize * 0.52;
  }
  return Math.ceil(w);
}

function renderBadge(leftText: string, rightText: string, rightColor: string): string {
  const padX = 8;
  const leftTextW = estimateTextWidth(leftText);
  const rightTextW = estimateTextWidth(rightText);
  const leftW = leftTextW + padX * 2;
  const rightW = rightTextW + padX * 2;
  const totalW = leftW + rightW;
  const h = 20;

  const leftTextX = leftW / 2;
  const rightTextX = leftW + rightW / 2;

  // Build the badge — no external font, uses the SVG spec's generic family stack.
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="${h}" role="img" aria-label="${leftText}: ${rightText}">
  <title>${leftText}: ${rightText}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".12"/>
    <stop offset="1" stop-opacity=".15"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalW}" height="${h}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${leftW}" height="${h}" fill="${PILL_LEFT_COLOR}"/>
    <rect x="${leftW}" width="${rightW}" height="${h}" fill="${rightColor}"/>
    <rect width="${totalW}" height="${h}" fill="url(#s)"/>
  </g>
  <g fill="${PILL_TEXT_COLOR}" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" font-weight="600">
    <text x="${leftTextX}" y="14">${leftText}</text>
    <text x="${rightTextX}" y="14">${rightText}</text>
  </g>
</svg>`;
}

function cacheHeaders(seconds: number) {
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
    const svg = renderBadge(PILL_LEFT_TEXT, 'invalid', RISK_COLORS.UNKNOWN);
    return new Response(svg, { status: 200, headers: cacheHeaders(60) });
  }

  try {
    const db = (locals as any).runtime.env.DB as D1Database;
    const scan = await scanOrCache(db, repoId);
    const right = `${scan.risk_level} ${scan.risk_score}/100`;
    const color = RISK_COLORS[scan.risk_level] || RISK_COLORS.UNKNOWN;
    const svg = renderBadge(PILL_LEFT_TEXT, right, color);
    // Cache badges for 10 minutes — balance freshness with viral traffic load.
    return new Response(svg, { status: 200, headers: cacheHeaders(600) });
  } catch {
    const svg = renderBadge(PILL_LEFT_TEXT, 'unknown', RISK_COLORS.UNKNOWN);
    return new Response(svg, { status: 200, headers: cacheHeaders(60) });
  }
};
