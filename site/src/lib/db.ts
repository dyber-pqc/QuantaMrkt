// Typed D1 query helpers for QuantaMrkt

// ---- Interfaces ----

export interface Model {
  id: number;
  slug: string;
  name: string;
  author: string;
  description: string | null;
  tags: string | null;
  license: string | null;
  framework: string | null;
  parameters: string | null;
  downloads: number;
  likes: number;
  verified: number;
  category: string | null;
  source_url: string | null;
  source_platform: string | null;
  hf_repo_id: string | null;
  ollama_name: string | null;
  created_at: string;
  updated_at: string;
  // Joined fields
  latest_version?: string | null;
  version_count?: number;
  signature_count?: number;
  risk_level?: string | null;
  risk_score?: number | null;
}

export interface ModelDetail extends Model {
  versions: ModelVersion[];
  files: ModelFile[];
  signatures: Signature[];
  hndl: HndlAssessment | null;
}

export interface ModelVersion {
  id: number;
  model_id: number;
  version: string;
  manifest_hash: string | null;
  file_count: number;
  total_size: number;
  r2_manifest_key: string | null;
  created_at: string;
}

export interface ModelFile {
  id: number;
  version_id: number;
  filename: string;
  sha3_256_hash: string | null;
  size: number;
}

export interface Signature {
  id: number;
  version_id: number;
  signer_did: string;
  algorithm: string;
  signature_hex: string;
  attestation_type: string | null;
  signed_at: string;
}

export interface Agent {
  id: number;
  user_id: number | null;
  name: string;
  did: string;
  algorithm: string;
  public_key_hex: string | null;
  capabilities_json: string | null;
  status: string;
  created_at: string;
  source_url?: string | null;
  platform_signer_did?: string | null;
  platform_signature?: string | null;
}

export interface DbUser {
  id: number;
  github_id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string | null;
  tier: string;
  created_at: string;
}

export interface ActivityEntry {
  id: number;
  user_id: number | null;
  action: string;
  target: string | null;
  details: string | null;
  created_at: string;
}

export interface HndlAssessment {
  id: number;
  model_id: number;
  risk_level: string;
  risk_score: number;
  shelf_life_years: number | null;
  sensitivity: string | null;
  recommendation: string | null;
  assessed_at: string;
}

// ---- Models ----

export async function getModels(
  db: D1Database,
  opts: { q?: string; sort?: string; risk?: string; category?: string; limit?: number; offset?: number } = {},
): Promise<{ models: Model[]; total: number }> {
  const { q, sort, risk, category, limit = 20, offset = 0 } = opts;

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (q) {
    conditions.push('(m.name LIKE ? OR m.author LIKE ?)');
    params.push(`%${q}%`, `%${q}%`);
  }
  if (risk) {
    conditions.push('h.risk_level = ?');
    params.push(risk);
  }
  if (category) {
    conditions.push('m.category = ?');
    params.push(category);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  let orderBy: string;
  switch (sort) {
    case 'likes':
      orderBy = 'm.likes DESC';
      break;
    case 'updated':
      orderBy = 'm.updated_at DESC';
      break;
    case 'downloads':
    default:
      orderBy = 'm.downloads DESC';
      break;
  }

  // Count query
  const countSql = `
    SELECT COUNT(*) as total
    FROM models m
    LEFT JOIN hndl_assessments h ON h.model_id = m.id
    ${where}
  `;
  const countResult = await db.prepare(countSql).bind(...params).first<{ total: number }>();
  const total = countResult?.total ?? 0;

  // Data query
  const dataSql = `
    SELECT
      m.*,
      lv.version AS latest_version,
      (SELECT COUNT(*) FROM model_versions WHERE model_id = m.id) AS version_count,
      (SELECT COUNT(*) FROM signatures s
       JOIN model_versions mv ON mv.id = s.version_id
       WHERE mv.model_id = m.id) AS signature_count,
      h.risk_level,
      h.risk_score
    FROM models m
    LEFT JOIN (
      SELECT model_id, version, ROW_NUMBER() OVER (PARTITION BY model_id ORDER BY created_at DESC) AS rn
      FROM model_versions
    ) lv ON lv.model_id = m.id AND lv.rn = 1
    LEFT JOIN hndl_assessments h ON h.model_id = m.id
    ${where}
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `;

  const dataParams = [...params, limit, offset];
  const dataResult = await db.prepare(dataSql).bind(...dataParams).all<Model>();
  return { models: dataResult.results ?? [], total };
}

export async function getModelBySlug(db: D1Database, slug: string): Promise<ModelDetail | null> {
  const model = await db
    .prepare('SELECT * FROM models WHERE slug = ?')
    .bind(slug)
    .first<Model>();

  if (!model) return null;

  const [versionsResult, hndl] = await Promise.all([
    db.prepare('SELECT * FROM model_versions WHERE model_id = ? ORDER BY created_at DESC')
      .bind(model.id)
      .all<ModelVersion>(),
    db.prepare('SELECT * FROM hndl_assessments WHERE model_id = ? ORDER BY assessed_at DESC LIMIT 1')
      .bind(model.id)
      .first<HndlAssessment>(),
  ]);

  const versions = versionsResult.results ?? [];
  const versionIds = versions.map((v) => v.id);

  let files: ModelFile[] = [];
  let signatures: Signature[] = [];

  if (versionIds.length > 0) {
    const placeholders = versionIds.map(() => '?').join(',');
    const [filesResult, sigsResult] = await Promise.all([
      db.prepare(`SELECT * FROM model_files WHERE version_id IN (${placeholders})`)
        .bind(...versionIds)
        .all<ModelFile>(),
      db.prepare(`SELECT * FROM signatures WHERE version_id IN (${placeholders})`)
        .bind(...versionIds)
        .all<Signature>(),
    ]);
    files = filesResult.results ?? [];
    signatures = sigsResult.results ?? [];
  }

  // Count signatures for verified field
  const signatureCount = signatures.length;

  return {
    ...model,
    latest_version: versions[0]?.version ?? null,
    version_count: versions.length,
    signature_count: signatureCount,
    risk_level: hndl?.risk_level ?? null,
    risk_score: hndl?.risk_score ?? null,
    versions,
    files,
    signatures,
    hndl: hndl ?? null,
  };
}

export async function createModel(
  db: D1Database,
  data: {
    slug: string;
    name: string;
    author: string;
    description?: string;
    tags?: string;
    license?: string;
    framework?: string;
    parameters?: string;
  },
): Promise<Model> {
  const result = await db
    .prepare(
      `INSERT INTO models (slug, name, author, description, tags, license, framework, parameters, downloads, likes, verified, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, datetime('now'), datetime('now'))
       RETURNING *`,
    )
    .bind(
      data.slug,
      data.name,
      data.author,
      data.description ?? null,
      data.tags ?? null,
      data.license ?? null,
      data.framework ?? null,
      data.parameters ?? null,
    )
    .first<Model>();

  return result!;
}

// ---- Versions ----

export async function createVersion(
  db: D1Database,
  modelId: number,
  data: {
    version: string;
    manifestHash: string;
    r2ManifestKey?: string;
    files: { filename: string; hash: string; size: number }[];
    signatures: { signerDid: string; algorithm: string; signatureHex: string; attestationType?: string }[];
  },
): Promise<ModelVersion> {
  const fileCount = data.files.length;
  const totalSize = data.files.reduce((sum, f) => sum + f.size, 0);

  // Insert version
  const version = await db
    .prepare(
      `INSERT INTO model_versions (model_id, version, manifest_hash, file_count, total_size, r2_manifest_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
       RETURNING *`,
    )
    .bind(modelId, data.version, data.manifestHash, fileCount, totalSize, data.r2ManifestKey ?? null)
    .first<ModelVersion>();

  if (!version) throw new Error('Failed to insert version');

  // Insert files via batch
  const fileStmts = data.files.map((f) =>
    db
      .prepare('INSERT INTO model_files (version_id, filename, sha3_256_hash, size) VALUES (?, ?, ?, ?)')
      .bind(version.id, f.filename, f.hash, f.size),
  );

  // Insert signatures via batch
  const sigStmts = data.signatures.map((s) =>
    db
      .prepare(
        `INSERT INTO signatures (version_id, signer_did, algorithm, signature_hex, attestation_type, signed_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      )
      .bind(version.id, s.signerDid, s.algorithm, s.signatureHex, s.attestationType ?? null),
  );

  const batchStmts = [...fileStmts, ...sigStmts];
  if (batchStmts.length > 0) {
    await db.batch(batchStmts);
  }

  // Update model's updated_at and verified count
  const sigCount = data.signatures.length;
  if (sigCount > 0) {
    await db
      .prepare("UPDATE models SET updated_at = datetime('now'), verified = 1 WHERE id = ?")
      .bind(modelId)
      .run();
  } else {
    await db
      .prepare("UPDATE models SET updated_at = datetime('now') WHERE id = ?")
      .bind(modelId)
      .run();
  }

  return version;
}

// ---- Agents ----

export async function getAgents(
  db: D1Database,
  opts: { userId?: number } = {},
): Promise<Agent[]> {
  if (opts.userId != null) {
    const result = await db
      .prepare('SELECT * FROM agents WHERE user_id = ? ORDER BY created_at DESC')
      .bind(opts.userId)
      .all<Agent>();
    return result.results ?? [];
  }
  const result = await db
    .prepare('SELECT * FROM agents ORDER BY created_at DESC')
    .all<Agent>();
  return result.results ?? [];
}

export async function getAgentByDid(db: D1Database, did: string): Promise<Agent | null> {
  return db.prepare('SELECT * FROM agents WHERE did = ?').bind(did).first<Agent>();
}

export async function getAgentById(db: D1Database, id: number): Promise<Agent | null> {
  return db.prepare('SELECT * FROM agents WHERE id = ?').bind(id).first<Agent>();
}

export async function createAgent(
  db: D1Database,
  data: {
    userId?: number;
    name: string;
    did: string;
    algorithm: string;
    publicKeyHex?: string;
    capabilities?: string[];
  },
): Promise<Agent> {
  const capabilitiesJson = data.capabilities ? JSON.stringify(data.capabilities) : null;
  const result = await db
    .prepare(
      `INSERT INTO agents (user_id, name, did, algorithm, public_key_hex, capabilities_json, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', datetime('now'))
       RETURNING *`,
    )
    .bind(
      data.userId ?? null,
      data.name,
      data.did,
      data.algorithm,
      data.publicKeyHex ?? null,
      capabilitiesJson,
    )
    .first<Agent>();

  return result!;
}

// ---- Users ----

export async function upsertUser(
  db: D1Database,
  data: { github_id: number; login: string; name: string | null; email: string | null; avatar_url: string },
): Promise<DbUser> {
  const result = await db
    .prepare(
      `INSERT INTO users (github_id, login, name, email, avatar_url, tier, created_at)
       VALUES (?, ?, ?, ?, ?, 'free', datetime('now'))
       ON CONFLICT(github_id) DO UPDATE SET
         login = excluded.login,
         name = excluded.name,
         email = excluded.email,
         avatar_url = excluded.avatar_url
       RETURNING *`,
    )
    .bind(data.github_id, data.login, data.name, data.email, data.avatar_url)
    .first<DbUser>();

  return result!;
}

export async function getUserByGithubId(db: D1Database, githubId: number): Promise<DbUser | null> {
  return db.prepare('SELECT * FROM users WHERE github_id = ?').bind(githubId).first<DbUser>();
}

export async function getUserStats(
  db: D1Database,
  userId: number,
): Promise<{ modelCount: number; agentCount: number; verificationCount: number }> {
  const [models, agents, verifications] = await Promise.all([
    db.prepare('SELECT COUNT(*) as c FROM models WHERE author = (SELECT login FROM users WHERE id = ?)').bind(userId).first<{ c: number }>(),
    db.prepare('SELECT COUNT(*) as c FROM agents WHERE user_id = ?').bind(userId).first<{ c: number }>(),
    db.prepare(
      `SELECT COUNT(*) as c FROM signatures s
       JOIN model_versions mv ON mv.id = s.version_id
       JOIN models m ON m.id = mv.model_id
       WHERE m.author = (SELECT login FROM users WHERE id = ?)`,
    ).bind(userId).first<{ c: number }>(),
  ]);

  return {
    modelCount: models?.c ?? 0,
    agentCount: agents?.c ?? 0,
    verificationCount: verifications?.c ?? 0,
  };
}

export async function getUserModels(db: D1Database, userLogin: string): Promise<Model[]> {
  const result = await db
    .prepare(
      `SELECT m.*,
        (SELECT COUNT(*) FROM signatures s JOIN model_versions mv ON mv.id = s.version_id WHERE mv.model_id = m.id) AS signature_count,
        h.risk_level,
        h.risk_score
       FROM models m
       LEFT JOIN hndl_assessments h ON h.model_id = m.id
       WHERE m.author = ?
       ORDER BY m.updated_at DESC`,
    )
    .bind(userLogin)
    .all<Model>();
  return result.results ?? [];
}

// ---- Activity ----

export async function getActivity(
  db: D1Database,
  opts: { userId?: number; limit?: number } = {},
): Promise<ActivityEntry[]> {
  const { userId, limit = 50 } = opts;

  if (userId != null) {
    const result = await db
      .prepare('SELECT * FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?')
      .bind(userId, limit)
      .all<ActivityEntry>();
    return result.results ?? [];
  }

  const result = await db
    .prepare('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ?')
    .bind(limit)
    .all<ActivityEntry>();
  return result.results ?? [];
}

export async function logActivity(
  db: D1Database,
  data: { userId?: number; action: string; target?: string; details?: string },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO activity_log (user_id, action, target, details, created_at)
       VALUES (?, ?, ?, ?, datetime('now'))`,
    )
    .bind(data.userId ?? null, data.action, data.target ?? null, data.details ?? null)
    .run();
}

// ---- Explore ----

export async function getTrendingModels(db: D1Database, limit: number = 10): Promise<Model[]> {
  const result = await db
    .prepare(
      `SELECT m.*,
        lv.version AS latest_version,
        (SELECT COUNT(*) FROM signatures s JOIN model_versions mv ON mv.id = s.version_id WHERE mv.model_id = m.id) AS signature_count,
        h.risk_level,
        h.risk_score
       FROM models m
       LEFT JOIN (
         SELECT model_id, version, ROW_NUMBER() OVER (PARTITION BY model_id ORDER BY created_at DESC) AS rn
         FROM model_versions
       ) lv ON lv.model_id = m.id AND lv.rn = 1
       LEFT JOIN hndl_assessments h ON h.model_id = m.id
       ORDER BY m.downloads DESC
       LIMIT ?`,
    )
    .bind(limit)
    .all<Model>();
  return result.results ?? [];
}

export async function getRecentVerifications(
  db: D1Database,
  limit: number = 10,
): Promise<{ model_name: string; model_author: string; signer: string; algorithm: string; signed_at: string }[]> {
  const result = await db
    .prepare(
      `SELECT m.name AS model_name, m.author AS model_author, s.signer_did AS signer, s.algorithm, s.signed_at
       FROM signatures s
       JOIN model_versions mv ON mv.id = s.version_id
       JOIN models m ON m.id = mv.model_id
       ORDER BY s.signed_at DESC
       LIMIT ?`,
    )
    .bind(limit)
    .all<{ model_name: string; model_author: string; signer: string; algorithm: string; signed_at: string }>();
  return result.results ?? [];
}

export async function getHndlLeaderboard(
  db: D1Database,
  limit: number = 10,
): Promise<{ name: string; author: string; slug: string; risk_score: number; risk_level: string; shelf_life: number | null; recommendation: string | null }[]> {
  const result = await db
    .prepare(
      `SELECT m.name, m.author, m.slug, h.risk_score, h.risk_level, h.shelf_life_years AS shelf_life, h.recommendation
       FROM hndl_assessments h
       JOIN models m ON m.id = h.model_id
       ORDER BY h.risk_score DESC
       LIMIT ?`,
    )
    .bind(limit)
    .all<{ name: string; author: string; slug: string; risk_score: number; risk_level: string; shelf_life: number | null; recommendation: string | null }>();
  return result.results ?? [];
}
