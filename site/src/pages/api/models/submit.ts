import type { APIRoute } from 'astro';
import { createModel, createVersion, logActivity } from '../../../lib/db';
import { getApiUser } from '../../../lib/api-auth';
import { appendLogEntry, sha256 } from '../../../lib/transparency';

export const POST: APIRoute = async ({ request, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    // Require authentication
    const user = await getApiUser(locals, request);
    if (!user) {
      return json({ error: 'Unauthorized. Please sign in to submit models.' }, 401);
    }

    const body = (await request.json()) as Record<string, any>;
    const hfUrl = body.hf_url;

    if (!hfUrl || typeof hfUrl !== 'string') {
      return json({ error: 'Missing required field: hf_url' }, 400);
    }

    // Extract repo_id from URL
    let repoId: string;
    try {
      const u = new URL(hfUrl);
      if (!u.hostname.includes('huggingface.co')) {
        return json({ error: 'URL must be from huggingface.co' }, 400);
      }
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length < 2) {
        return json({ error: 'Invalid HuggingFace model URL. Expected format: https://huggingface.co/{org}/{model}' }, 400);
      }
      repoId = parts[0] + '/' + parts[1];
    } catch {
      return json({ error: 'Invalid URL format' }, 400);
    }

    // Fetch model info from HuggingFace API (with blobs for file sizes)
    const hfRes = await fetch(`https://huggingface.co/api/models/${repoId}?blobs=true`, {
      headers: { 'User-Agent': 'QuantaMrkt/1.0' },
    });

    if (!hfRes.ok) {
      if (hfRes.status === 404) {
        return json({ error: `Model "${repoId}" not found on HuggingFace.` }, 404);
      }
      return json({ error: `HuggingFace API error: ${hfRes.status}` }, 502);
    }

    const hfModel = (await hfRes.json()) as Record<string, any>;

    const modelId = hfModel.modelId || repoId;
    const [author, ...nameParts] = modelId.split('/');
    const modelName = nameParts.join('/') || modelId;
    const description = hfModel.description || hfModel.cardData?.description || null;
    const tags = hfModel.tags || [];
    const license = hfModel.cardData?.license || hfModel.license || null;
    const pipelineTag = hfModel.pipeline_tag || null;
    const downloads = hfModel.downloads || 0;
    const likes = hfModel.likes || 0;

    // Generate slug
    const slug = modelId.replace(/\//g, '--').toLowerCase();

    const db = (locals as any).runtime.env.DB as D1Database;

    // Check if model already exists
    const existing = await db
      .prepare('SELECT id, slug FROM models WHERE slug = ? OR hf_repo_id = ?')
      .bind(slug, repoId)
      .first<{ id: number; slug: string }>();

    if (existing) {
      return json({ slug: existing.slug, success: true, message: 'Model already registered.' });
    }

    // Create model
    const model = await db
      .prepare(
        `INSERT INTO models (slug, name, author, description, tags, license, framework, parameters, downloads, likes, verified, category, source_url, source_platform, hf_repo_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'huggingface', ?, datetime('now'), datetime('now'))
         RETURNING *`,
      )
      .bind(
        slug,
        modelName,
        author,
        description,
        JSON.stringify(tags),
        license,
        pipelineTag, // framework = pipeline_tag
        null, // parameters
        downloads,
        likes,
        pipelineTag, // category = pipeline_tag
        `https://huggingface.co/${repoId}`,
        repoId,
      )
      .first<{ id: number; slug: string }>();

    if (!model) {
      return json({ error: 'Failed to create model record.' }, 500);
    }

    // Build file list from siblings
    const siblings = hfModel.siblings || [];
    const files: { filename: string; hash: string; size: number }[] = siblings.map((f: any) => ({
      filename: f.rfilename || f.filename || 'unknown',
      hash: f.lfs?.sha256 || f.sha || 'pending-verification',
      size: f.lfs?.size || f.size || 0,
    }));

    // Generate a pseudo manifest hash
    const fileHashes = files.map((f) => f.hash).join('|');
    const manifestHash = await sha256(`${repoId}|${new Date().toISOString()}|${fileHashes}`);

    // Generate a pseudo PQC registry signature
    const sigPayload = `registry:${slug}:${manifestHash}`;
    const signatureHex = await sha256(sigPayload + ':ml-dsa-65');

    // Create version with files and registry signature
    await createVersion(db, model.id, {
      version: 'v1.0.0',
      manifestHash,
      r2ManifestKey: `manifests/${slug}/v1.0.0.json`,
      files,
      signatures: [
        {
          signerDid: 'did:quantamrkt:registry:shield-v1',
          algorithm: 'ML-DSA-65',
          signatureHex,
          attestationType: 'registry',
        },
      ],
    });

    // Calculate and store HNDL assessment
    let riskScore = 40;
    const sizeGB = files.reduce((sum, f) => sum + f.size, 0) / (1024 * 1024 * 1024);
    if (sizeGB > 100) riskScore += 30;
    else if (sizeGB > 10) riskScore += 20;
    else if (sizeGB > 1) riskScore += 10;

    if (downloads > 1000000) riskScore += 15;
    else if (downloads > 100000) riskScore += 10;
    else if (downloads > 10000) riskScore += 5;

    if (['text-generation', 'image-generation', 'text-to-image', 'image-text-to-text'].includes(pipelineTag || '')) {
      riskScore += 10;
    }

    if (!license || (license && (license.includes('proprietary') || license.includes('non-commercial')))) {
      riskScore += 5;
    }

    riskScore = Math.min(100, riskScore);
    let riskLevel: string;
    if (riskScore >= 80) riskLevel = 'CRITICAL';
    else if (riskScore >= 60) riskLevel = 'HIGH';
    else if (riskScore >= 40) riskLevel = 'MEDIUM';
    else riskLevel = 'LOW';

    let shelfLifeYears: number;
    if (riskScore >= 80) shelfLifeYears = 15;
    else if (riskScore >= 60) shelfLifeYears = 10;
    else if (riskScore >= 40) shelfLifeYears = 7;
    else shelfLifeYears = 5;

    let recommendation: string;
    if (riskLevel === 'CRITICAL') recommendation = 'Immediate migration to PQC recommended.';
    else if (riskLevel === 'HIGH') recommendation = 'Plan PQC migration within 6 months.';
    else if (riskLevel === 'MEDIUM') recommendation = 'Monitor and prepare migration plan.';
    else recommendation = 'Follow PQC best practices.';

    await db
      .prepare(
        `INSERT INTO hndl_assessments (model_id, risk_level, risk_score, shelf_life_years, sensitivity, recommendation, assessed_at)
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
      )
      .bind(model.id, riskLevel, riskScore, shelfLifeYears, pipelineTag, recommendation)
      .run();

    // Log activity
    await logActivity(db, {
      userId: user.id,
      action: 'model.submit',
      target: slug,
      details: `Submitted model ${modelName} from HuggingFace (${repoId})`,
    });

    // Append to transparency log
    await appendLogEntry(db, {
      action: 'model:submitted',
      actor_did: undefined,
      target_type: 'model',
      target_id: slug,
      metadata: {
        name: modelName,
        author,
        source: 'huggingface',
        hf_repo_id: repoId,
        file_count: files.length,
        risk_level: riskLevel,
        risk_score: riskScore,
      },
    });

    return json({ slug: model.slug, success: true });
  } catch (err: any) {
    console.error('Model submit error:', err);
    return json({ error: err.message || 'Internal server error' }, 500);
  }
};
