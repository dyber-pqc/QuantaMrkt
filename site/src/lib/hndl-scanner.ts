// HNDL Scanner — server-side logic for scanning any HuggingFace URL and
// computing a quantum risk assessment. Used by both the API endpoint and
// the shareable public page.

export interface HFModelSummary {
  id: string;
  author?: string;
  downloads?: number;
  likes?: number;
  tags?: string[];
  pipeline_tag?: string | null;
  library_name?: string;
  lastModified?: string;
  cardData?: Record<string, any>;
  siblings?: { rfilename: string; size?: number; lfs?: { sha256?: string; size?: number } }[];
  description?: string;
  license?: string;
  private?: boolean;
}

export interface HNDLScanResult {
  hf_repo_id: string;
  model_name: string;
  author: string;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  risk_score: number;             // 0-100
  shelf_life_years: number;
  recommendation: string;
  downloads: number;
  likes: number;
  pipeline_tag: string | null;
  license: string | null;
  total_size: number;             // bytes
  file_count: number;
  breakdown: BreakdownEntry[];    // what drives the score
  scanned_at: string;
  fresh: boolean;                 // true if freshly computed, false if from cache
  scan_count: number;
}

export interface BreakdownEntry {
  factor: string;
  points: number;
  reason: string;
}

// ---- URL parsing ---------------------------------------------------------

/** Parse a HuggingFace URL / slug / repo-id into an "org/repo" identifier. */
export function parseHfRepo(input: string): string | null {
  if (!input) return null;
  const trimmed = input.trim();

  // Already in "org/repo" form
  const repoMatch = trimmed.match(/^[a-zA-Z0-9][a-zA-Z0-9_-]*\/[a-zA-Z0-9][a-zA-Z0-9._-]*$/);
  if (repoMatch) return trimmed;

  // Full URL form
  try {
    const u = new URL(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
    if (!u.hostname.includes('huggingface.co')) return null;
    const parts = u.pathname.split('/').filter(Boolean);
    // Skip /datasets/ or /spaces/ prefixes for the scanner (models only)
    if (parts.length >= 2) {
      if (parts[0] === 'datasets' || parts[0] === 'spaces') {
        return `${parts[1]}/${parts[2] || ''}`.replace(/\/$/, '');
      }
      return `${parts[0]}/${parts[1]}`;
    }
  } catch {
    // not a valid URL
  }
  return null;
}

/** Slug form used in our DB (e.g. "meta-llama--llama-3.1-8b-instruct"). */
export function repoToSlug(repoId: string): string {
  return repoId.replace(/\//g, '--').toLowerCase();
}

/** Inverse of repoToSlug — "org--repo" -> "org/repo". */
export function slugToRepo(slug: string): string {
  return slug.replace(/--/g, '/');
}

// ---- HNDL calculation ----------------------------------------------------

export function calculateHNDL(model: HFModelSummary): {
  risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  shelf_life_years: number;
  recommendation: string;
  breakdown: BreakdownEntry[];
  total_size: number;
} {
  const breakdown: BreakdownEntry[] = [];
  let score = 40;
  breakdown.push({ factor: 'Baseline', points: 40, reason: 'All AI artifacts have baseline HNDL exposure' });

  // Size (bigger = more value = higher risk)
  const totalSize = (model.siblings || []).reduce((acc, s) => acc + (s.lfs?.size || s.size || 0), 0);
  const sizeGB = totalSize / (1024 * 1024 * 1024);
  if (sizeGB > 100) {
    score += 30;
    breakdown.push({ factor: 'Size', points: 30, reason: `${sizeGB.toFixed(0)}GB+ — frontier model, highest theft value` });
  } else if (sizeGB > 10) {
    score += 20;
    breakdown.push({ factor: 'Size', points: 20, reason: `${sizeGB.toFixed(1)}GB — large model with significant training cost` });
  } else if (sizeGB > 1) {
    score += 10;
    breakdown.push({ factor: 'Size', points: 10, reason: `${sizeGB.toFixed(1)}GB — meaningful compute invested` });
  } else {
    breakdown.push({ factor: 'Size', points: 0, reason: `${sizeGB.toFixed(2)}GB — small artifact` });
  }

  // Downloads (popularity = more adversary interest)
  const downloads = model.downloads || 0;
  if (downloads > 1_000_000) {
    score += 15;
    breakdown.push({ factor: 'Adversary interest', points: 15, reason: `${(downloads / 1_000_000).toFixed(1)}M downloads — high-profile target` });
  } else if (downloads > 100_000) {
    score += 10;
    breakdown.push({ factor: 'Adversary interest', points: 10, reason: `${(downloads / 1000).toFixed(0)}K downloads — popular model` });
  } else if (downloads > 10_000) {
    score += 5;
    breakdown.push({ factor: 'Adversary interest', points: 5, reason: `${(downloads / 1000).toFixed(0)}K downloads — notable usage` });
  }

  // Pipeline (some artifact types are more valuable)
  const pipeline = model.pipeline_tag || '';
  const highValuePipelines = ['text-generation', 'image-generation', 'text-to-image', 'image-text-to-text', 'automatic-speech-recognition'];
  if (highValuePipelines.includes(pipeline)) {
    score += 10;
    breakdown.push({ factor: 'Artifact type', points: 10, reason: `${pipeline} — high value in commercial markets` });
  }

  // License (proprietary = higher stake)
  const license = String(model.cardData?.license || model.license || '').toLowerCase();
  if (!license || license.includes('proprietary') || license.includes('non-commercial')) {
    score += 5;
    breakdown.push({ factor: 'License', points: 5, reason: license ? `${license} — restricted commercial use` : 'No license declared' });
  }

  // Age (older = more harvest window)
  const lastModified = model.lastModified ? new Date(model.lastModified).getTime() : Date.now();
  const ageDays = Math.max(0, (Date.now() - lastModified) / (1000 * 60 * 60 * 24));
  if (ageDays > 365) {
    score += 5;
    breakdown.push({ factor: 'Exposure window', points: 5, reason: `${Math.floor(ageDays / 365)} years of public availability — harvested long ago` });
  }

  score = Math.min(100, Math.max(0, score));

  let risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  if (score >= 80) risk_level = 'CRITICAL';
  else if (score >= 60) risk_level = 'HIGH';
  else if (score >= 40) risk_level = 'MEDIUM';
  else risk_level = 'LOW';

  let shelf_life_years: number;
  if (score >= 80) shelf_life_years = 15;
  else if (score >= 60) shelf_life_years = 10;
  else if (score >= 40) shelf_life_years = 7;
  else shelf_life_years = 5;

  let recommendation: string;
  if (risk_level === 'CRITICAL') recommendation = 'Immediate PQC migration required. Sign with ML-DSA-87 and publish to a transparency log. Data harvested now will be decryptable once CRQC exists.';
  else if (risk_level === 'HIGH') recommendation = 'Plan PQC migration within 6 months. Classical crypto on this artifact is a liability before CNSA 2.0 deadlines.';
  else if (risk_level === 'MEDIUM') recommendation = 'Monitor and prepare migration plan. Publishers should dual-sign with PQC during transition.';
  else recommendation = 'Follow PQC best practices. Keep SHA-256 + ML-DSA-65 integrity signatures current.';

  return { risk_score: score, risk_level, shelf_life_years, recommendation, breakdown, total_size: totalSize };
}

// ---- Fetch + scan --------------------------------------------------------

/** Fetch HF model metadata. Throws on failure. */
export async function fetchHfModel(repoId: string): Promise<HFModelSummary> {
  const res = await fetch(`https://huggingface.co/api/models/${repoId}?blobs=true`, {
    headers: { 'User-Agent': 'QuantaMrkt-HNDL-Scanner/1.0' },
  });
  if (!res.ok) {
    throw new Error(`HuggingFace API returned ${res.status} for ${repoId}`);
  }
  return (await res.json()) as HFModelSummary;
}

/** Run a fresh scan and persist to cache. */
export async function runHndlScan(
  db: D1Database,
  repoId: string,
): Promise<HNDLScanResult> {
  const model = await fetchHfModel(repoId);
  const hndl = calculateHNDL(model);

  const [author, ...nameParts] = repoId.split('/');
  const modelName = nameParts.join('/') || repoId;
  const downloads = model.downloads || 0;
  const likes = model.likes || 0;
  const pipeline_tag = model.pipeline_tag || null;
  const license = model.cardData?.license || model.license || null;
  const file_count = (model.siblings || []).length;

  const scannedAt = new Date().toISOString().replace('T', ' ').replace('Z', '').split('.')[0];
  const details = JSON.stringify({ breakdown: hndl.breakdown });

  // Upsert: insert fresh, or bump scan_count if exists
  await db
    .prepare(
      `INSERT INTO hndl_scans (
         hf_repo_id, risk_level, risk_score, shelf_life_years, recommendation,
         model_name, author, downloads, likes, pipeline_tag, license,
         total_size, file_count, details_json, scanned_at, scan_count, last_viewed_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
       ON CONFLICT(hf_repo_id) DO UPDATE SET
         risk_level = excluded.risk_level,
         risk_score = excluded.risk_score,
         shelf_life_years = excluded.shelf_life_years,
         recommendation = excluded.recommendation,
         model_name = excluded.model_name,
         author = excluded.author,
         downloads = excluded.downloads,
         likes = excluded.likes,
         pipeline_tag = excluded.pipeline_tag,
         license = excluded.license,
         total_size = excluded.total_size,
         file_count = excluded.file_count,
         details_json = excluded.details_json,
         scanned_at = excluded.scanned_at,
         scan_count = hndl_scans.scan_count + 1,
         last_viewed_at = excluded.last_viewed_at`,
    )
    .bind(
      repoId, hndl.risk_level, hndl.risk_score, hndl.shelf_life_years, hndl.recommendation,
      modelName, author, downloads, likes, pipeline_tag, license ? String(license) : null,
      hndl.total_size, file_count, details, scannedAt, scannedAt,
    )
    .run();

  const row = await db
    .prepare(`SELECT scan_count FROM hndl_scans WHERE hf_repo_id = ?`)
    .bind(repoId)
    .first<{ scan_count: number }>();

  return {
    hf_repo_id: repoId,
    model_name: modelName,
    author,
    risk_level: hndl.risk_level,
    risk_score: hndl.risk_score,
    shelf_life_years: hndl.shelf_life_years,
    recommendation: hndl.recommendation,
    downloads,
    likes,
    pipeline_tag,
    license: license ? String(license) : null,
    total_size: hndl.total_size,
    file_count,
    breakdown: hndl.breakdown,
    scanned_at: scannedAt,
    fresh: true,
    scan_count: row?.scan_count ?? 1,
  };
}

/** Fetch cached scan, or null if missing/stale. */
export async function getCachedScan(
  db: D1Database,
  repoId: string,
  maxAgeHours: number = 6,
): Promise<HNDLScanResult | null> {
  const row = await db
    .prepare(
      `SELECT * FROM hndl_scans
       WHERE hf_repo_id = ?
         AND scanned_at > datetime('now', ?)`,
    )
    .bind(repoId, `-${maxAgeHours} hours`)
    .first<any>();

  if (!row) return null;

  // Bump view count
  await db
    .prepare(`UPDATE hndl_scans SET last_viewed_at = datetime('now') WHERE hf_repo_id = ?`)
    .bind(repoId)
    .run();

  let breakdown: BreakdownEntry[] = [];
  try {
    const parsed = JSON.parse(row.details_json || '{}');
    breakdown = parsed.breakdown || [];
  } catch {
    // ignore
  }

  return {
    hf_repo_id: row.hf_repo_id,
    model_name: row.model_name,
    author: row.author,
    risk_level: row.risk_level,
    risk_score: row.risk_score,
    shelf_life_years: row.shelf_life_years,
    recommendation: row.recommendation,
    downloads: row.downloads ?? 0,
    likes: row.likes ?? 0,
    pipeline_tag: row.pipeline_tag,
    license: row.license,
    total_size: row.total_size ?? 0,
    file_count: row.file_count ?? 0,
    breakdown,
    scanned_at: row.scanned_at,
    fresh: false,
    scan_count: row.scan_count ?? 1,
  };
}

/** Full flow: return cached if fresh, else run a new scan. */
export async function scanOrCache(
  db: D1Database,
  repoId: string,
  forceRefresh: boolean = false,
): Promise<HNDLScanResult> {
  if (!forceRefresh) {
    const cached = await getCachedScan(db, repoId);
    if (cached) return cached;
  }
  return runHndlScan(db, repoId);
}
