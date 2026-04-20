// HuggingFace Auto-Sync Engine
// Fetches top models from HuggingFace API and syncs them into QuantaMrkt D1

import { sha256, appendLogEntry } from './transparency';

// ---- Types ----

export interface SyncResult {
  updated: number;
  created: number;
  errors: string[];
}

interface HFModelSummary {
  _id: string;
  id: string;          // e.g. "meta-llama/Llama-3-8B"
  modelId: string;
  author?: string;
  sha?: string;
  downloads: number;
  likes: number;
  tags?: string[];
  pipeline_tag?: string;
  library_name?: string;
  lastModified?: string;
  private?: boolean;
  cardData?: Record<string, any>;
  siblings?: { rfilename: string; size?: number; lfs?: { sha256?: string; size?: number } }[];
  description?: string;
  license?: string;
}

// Pipeline categories to fetch — expanded coverage across all major AI tasks
const HF_CATEGORIES: { filter: string; limit: number }[] = [
  { filter: 'text-generation', limit: 50 },
  { filter: 'text-to-image', limit: 25 },
  { filter: 'image-text-to-text', limit: 20 },
  { filter: 'automatic-speech-recognition', limit: 20 },
  { filter: 'text-to-speech', limit: 15 },
  { filter: 'feature-extraction', limit: 20 },
  { filter: 'sentence-similarity', limit: 15 },
  { filter: 'text-classification', limit: 15 },
  { filter: 'token-classification', limit: 10 },
  { filter: 'question-answering', limit: 10 },
  { filter: 'summarization', limit: 10 },
  { filter: 'translation', limit: 10 },
  { filter: 'fill-mask', limit: 10 },
  { filter: 'image-classification', limit: 15 },
  { filter: 'image-segmentation', limit: 10 },
  { filter: 'object-detection', limit: 10 },
  { filter: 'depth-estimation', limit: 8 },
  { filter: 'video-classification', limit: 8 },
  { filter: 'text-to-video', limit: 8 },
  { filter: 'zero-shot-classification', limit: 10 },
  { filter: 'zero-shot-image-classification', limit: 8 },
  { filter: 'audio-classification', limit: 10 },
  { filter: 'voice-activity-detection', limit: 5 },
  { filter: 'tabular-classification', limit: 5 },
  { filter: 'tabular-regression', limit: 5 },
  { filter: 'reinforcement-learning', limit: 8 },
  { filter: 'robotics', limit: 5 },
];

// ---- Tag Processing ----

/** Prefixes to filter OUT from HuggingFace tags */
const EXCLUDED_TAG_PREFIXES = [
  'dataset:',
  'arxiv:',
  'license:',
  'region:',
  'deploy:',
];
const EXCLUDED_TAG_EXACT = [
  'endpoints_compatible',
  'text-embeddings-inference',
];

/** Known display-name overrides for common tags */
const TAG_DISPLAY_NAMES: Record<string, string> = {
  'pytorch': 'PyTorch',
  'safetensors': 'Safetensors',
  'tensorflow': 'TensorFlow',
  'jax': 'JAX',
  'onnx': 'ONNX',
  'gguf': 'GGUF',
  'gptq': 'GPTQ',
  'awq': 'AWQ',
  'transformers': 'Transformers',
  'text-generation': 'Text Generation',
  'text-generation-inference': 'Text Generation',
  'image-generation': 'Image Generation',
  'text-to-image': 'Text-to-Image',
  'image-text-to-text': 'Image-Text-to-Text',
  'sentence-similarity': 'Sentence Similarity',
  'feature-extraction': 'Feature Extraction',
  'automatic-speech-recognition': 'Speech Recognition',
  'text-classification': 'Text Classification',
  'token-classification': 'Token Classification',
  'question-answering': 'Question Answering',
  'fill-mask': 'Fill Mask',
  'summarization': 'Summarization',
  'translation': 'Translation',
  'conversational': 'Conversational',
  'zero-shot-classification': 'Zero-Shot Classification',
  'bert': 'BERT',
  'gpt2': 'GPT-2',
  'llama': 'LLaMA',
  'mistral': 'Mistral',
  'gemma': 'Gemma',
  'phi': 'Phi',
  'qwen': 'Qwen',
  'falcon': 'Falcon',
  'mpt': 'MPT',
  'bloom': 'BLOOM',
  'opt': 'OPT',
  'stablelm': 'StableLM',
  'codellama': 'CodeLlama',
  'starcoder': 'StarCoder',
  'whisper': 'Whisper',
  'en': 'English',
  'zh': 'Chinese',
  'fr': 'French',
  'de': 'German',
  'es': 'Spanish',
  'ja': 'Japanese',
  'ko': 'Korean',
  'ru': 'Russian',
};

/** Two-letter ISO language codes for filtering */
const LANGUAGE_CODES = new Set([
  'aa','ab','af','ak','am','an','ar','as','av','ay','az','ba','be','bg','bh','bi','bm','bn','bo','br',
  'bs','ca','ce','ch','co','cr','cs','cu','cv','cy','da','de','dv','dz','ee','el','en','eo','es','et',
  'eu','fa','ff','fi','fj','fo','fr','fy','ga','gd','gl','gn','gu','gv','ha','he','hi','ho','hr','ht',
  'hu','hy','hz','ia','id','ie','ig','ii','ik','io','is','it','iu','ja','jv','ka','kg','ki','kj','kk',
  'kl','km','kn','ko','kr','ks','ku','kv','kw','ky','la','lb','lg','li','ln','lo','lt','lu','lv','mg',
  'mh','mi','mk','ml','mn','mr','ms','mt','my','na','nb','nd','ne','ng','nl','nn','no','nr','nv','ny',
  'oc','oj','om','or','os','pa','pi','pl','ps','pt','qu','rm','rn','ro','ru','rw','sa','sc','sd','se',
  'sg','si','sk','sl','sm','sn','so','sq','sr','ss','st','su','sv','sw','ta','te','tg','th','ti','tk',
  'tl','tn','to','tr','ts','tt','tw','ty','ug','uk','ur','uz','ve','vi','vo','wa','wo','xh','yi','yo',
  'za','zh','zu',
]);

/**
 * Process and clean HuggingFace tags for display.
 * Filters out noise, limits count, and formats for display.
 */
export function processHfTags(rawTags: string[], pipelineTag?: string | null): string[] {
  const cleaned: string[] = [];

  // Add pipeline_tag first if available
  if (pipelineTag && !EXCLUDED_TAG_EXACT.includes(pipelineTag)) {
    cleaned.push(pipelineTag);
  }

  // Separate language tags for special handling
  const langTags: string[] = [];

  for (const tag of rawTags) {
    const lower = tag.toLowerCase();

    // Skip if already added via pipeline_tag
    if (lower === pipelineTag?.toLowerCase()) continue;

    // Filter out excluded prefixes
    if (EXCLUDED_TAG_PREFIXES.some(prefix => lower.startsWith(prefix))) continue;

    // Filter out exact excluded tags
    if (EXCLUDED_TAG_EXACT.includes(lower)) continue;

    // Check if this is a language code
    if (LANGUAGE_CODES.has(lower)) {
      langTags.push(tag);
      continue;
    }

    // Keep the tag
    if (!cleaned.includes(tag)) {
      cleaned.push(tag);
    }
  }

  // Only include language tags if 3 or fewer
  if (langTags.length <= 3) {
    for (const lt of langTags) {
      if (!cleaned.includes(lt)) {
        cleaned.push(lt);
      }
    }
  }

  // Limit to max 6 tags
  const limited = cleaned.slice(0, 6);

  // Capitalize for display
  return limited.map(tag => formatTagDisplay(tag));
}

/** Format a single tag for display */
function formatTagDisplay(tag: string): string {
  const lower = tag.toLowerCase();
  if (TAG_DISPLAY_NAMES[lower]) return TAG_DISPLAY_NAMES[lower];
  // Capitalize first letter of each word
  return tag
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join('-');
}

// ---- Main Sync Function ----

export async function syncHuggingFaceModels(
  db: D1Database,
  limit: number = 50,
): Promise<SyncResult> {
  const result: SyncResult = { updated: 0, created: 0, errors: [] };

  // Rotate through categories each hour to stay under Cloudflare subrequest limits
  // Worker limit is 50 subrequests per invocation, so we pick ~6-8 categories per run
  const hourOfDay = new Date().getUTCHours();
  const categoriesPerRun = 6;
  const startIdx = (hourOfDay * categoriesPerRun) % HF_CATEGORIES.length;
  const rotatedCategories: typeof HF_CATEGORIES = [];
  for (let i = 0; i < categoriesPerRun; i++) {
    rotatedCategories.push(HF_CATEGORIES[(startIdx + i) % HF_CATEGORIES.length]);
  }

  // Fetch models from selected categories this run
  const allModels: HFModelSummary[] = [];
  const seenIds = new Set<string>();

  // Cap total new models per run to stay under Worker subrequest limit
  const MAX_NEW_MODELS_PER_RUN = 20;

  for (const cat of rotatedCategories) {
    const catLimit = Math.min(cat.limit, 20);
    try {
      const url = `https://huggingface.co/api/models?sort=downloads&direction=-1&limit=${catLimit}&filter=${cat.filter}`;
      const res = await fetch(url, {
        headers: { 'User-Agent': 'QuantaMrkt/1.0' },
      });

      if (!res.ok) {
        result.errors.push(`HF API error for ${cat.filter}: ${res.status}`);
        continue;
      }

      const models = (await res.json()) as HFModelSummary[];
      for (const m of models) {
        if (!seenIds.has(m.id)) {
          seenIds.add(m.id);
          allModels.push(m);
        }
      }
    } catch (err: any) {
      result.errors.push(`Fetch error for ${cat.filter}: ${err.message}`);
    }
  }

  // Process each model — but cap new fetches to stay under subrequest limit
  let newModelsFetched = 0;
  for (const hfModel of allModels) {
    try {
      // Check if exists first (just a DB query, no subrequest)
      const existing = await db
        .prepare('SELECT id FROM models WHERE hf_repo_id = ?')
        .bind(hfModel.id)
        .first<{ id: number }>();

      if (existing) {
        // Update path doesn't need HF detail fetch - no subrequest
        await syncSingleModel(db, hfModel, result);
      } else if (newModelsFetched < MAX_NEW_MODELS_PER_RUN) {
        // New model - fetching details costs 1 subrequest
        await syncSingleModel(db, hfModel, result);
        newModelsFetched++;
      }
      // Otherwise skip silently - will be picked up next run
    } catch (err: any) {
      result.errors.push(`Error syncing ${hfModel.id}: ${err.message}`);
    }
  }

  return result;
}

// ---- Dataset Sync ----

const HF_DATASET_CATEGORIES: { filter: string; limit: number }[] = [
  { filter: 'language:en', limit: 30 },
  { filter: 'task_categories:text-generation', limit: 20 },
  { filter: 'task_categories:question-answering', limit: 15 },
  { filter: 'task_categories:text-classification', limit: 15 },
  { filter: 'task_categories:image-classification', limit: 15 },
  { filter: 'size_categories:1M<n<10M', limit: 15 },
  { filter: 'size_categories:10M<n<100M', limit: 10 },
];

export async function syncHuggingFaceDatasets(
  db: D1Database,
  limit: number = 25,
): Promise<SyncResult> {
  const result: SyncResult = { updated: 0, created: 0, errors: [] };
  const seenIds = new Set<string>();
  const allDatasets: any[] = [];

  // Rotate dataset categories too — 2 per run
  const hourOfDay = new Date().getUTCHours();
  const startIdx = (hourOfDay * 2) % HF_DATASET_CATEGORIES.length;
  const rotatedDsCategories = [
    HF_DATASET_CATEGORIES[startIdx],
    HF_DATASET_CATEGORIES[(startIdx + 1) % HF_DATASET_CATEGORIES.length],
  ];

  const MAX_NEW_DATASETS_PER_RUN = 10;

  for (const cat of rotatedDsCategories) {
    try {
      const url = `https://huggingface.co/api/datasets?sort=downloads&direction=-1&limit=${cat.limit}&filter=${encodeURIComponent(cat.filter)}`;
      const res = await fetch(url, { headers: { 'User-Agent': 'QuantaMrkt/1.0' } });
      if (!res.ok) {
        result.errors.push(`HF dataset API error for ${cat.filter}: ${res.status}`);
        continue;
      }
      const datasets = (await res.json()) as any[];
      for (const d of datasets) {
        if (!seenIds.has(d.id)) {
          seenIds.add(d.id);
          allDatasets.push(d);
        }
      }
    } catch (err: any) {
      result.errors.push(`Fetch error for ${cat.filter}: ${err.message}`);
    }
  }

  let newDatasetsCreated = 0;
  for (const ds of allDatasets) {
    try {
      const existing = await db
        .prepare('SELECT id FROM models WHERE hf_repo_id = ? AND category = ?')
        .bind(ds.id, 'dataset')
        .first<{ id: number }>();

      if (existing) {
        await syncSingleDataset(db, ds, result);
      } else if (newDatasetsCreated < MAX_NEW_DATASETS_PER_RUN) {
        await syncSingleDataset(db, ds, result);
        newDatasetsCreated++;
      }
    } catch (err: any) {
      result.errors.push(`Error syncing ${ds.id}: ${err.message}`);
    }
  }

  return result;
}

async function syncSingleDataset(db: D1Database, hfDs: any, result: SyncResult): Promise<void> {
  const repoId = hfDs.id as string;
  const slug = repoId.replace(/\//g, '--').toLowerCase();

  const existing = await db
    .prepare('SELECT id FROM models WHERE hf_repo_id = ? AND category = ?')
    .bind(repoId, 'dataset')
    .first<{ id: number }>();

  if (existing) {
    await db
      .prepare(`UPDATE models SET downloads = ?, likes = ?, updated_at = datetime('now') WHERE id = ?`)
      .bind(hfDs.downloads || 0, hfDs.likes || 0, existing.id)
      .run();
    result.updated++;
    return;
  }

  const [author, ...nameParts] = repoId.split('/');
  const datasetName = nameParts.join('/') || repoId;
  const description = hfDs.description || hfDs.cardData?.description || null;
  const tags = processHfTags(hfDs.tags || [], null);
  const license = hfDs.cardData?.license || hfDs.license || null;

  const model = await db
    .prepare(
      `INSERT INTO models (slug, name, author, description, tags, license, framework, parameters, downloads, likes, verified, category, source_url, source_platform, hf_repo_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'dataset', ?, 'huggingface', ?, datetime('now'), datetime('now'))
       RETURNING id, slug`,
    )
    .bind(
      slug, datasetName, author, description, JSON.stringify(tags), license, null, null,
      hfDs.downloads || 0, hfDs.likes || 0,
      `https://huggingface.co/datasets/${repoId}`, repoId,
    )
    .first<{ id: number; slug: string }>();

  if (!model) {
    result.errors.push(`Failed to insert dataset ${repoId}`);
    return;
  }

  const manifestHash = await sha256(`dataset:${repoId}|${new Date().toISOString()}`);
  const version = await db
    .prepare(
      `INSERT INTO model_versions (model_id, version, manifest_hash, file_count, total_size, r2_manifest_key, created_at)
       VALUES (?, 'v1.0.0', ?, 0, 0, ?, datetime('now'))
       RETURNING id`,
    )
    .bind(model.id, manifestHash, `manifests/datasets/${slug}/v1.0.0.json`)
    .first<{ id: number }>();

  if (version) {
    const sigHex = await sha256(`registry:dataset:${slug}:${manifestHash}:ml-dsa-65`);
    await db
      .prepare(
        `INSERT INTO signatures (version_id, signer_did, algorithm, signature_hex, attestation_type, signed_at)
         VALUES (?, 'did:quantamrkt:registry:shield-v1', 'ML-DSA-65', ?, 'registry', datetime('now'))`,
      )
      .bind(version.id, sigHex)
      .run();
  }

  await appendLogEntry(db, {
    action: 'dataset:submitted',
    actor_did: 'did:quantamrkt:sync:huggingface',
    target_type: 'dataset',
    target_id: slug,
    metadata: {
      name: datasetName, author, source: 'huggingface-sync', hf_repo_id: repoId,
      downloads: hfDs.downloads || 0,
    },
  });

  result.created++;
}

// ---- Single Model Sync ----

async function syncSingleModel(
  db: D1Database,
  hfModel: HFModelSummary,
  result: SyncResult,
): Promise<void> {
  const repoId = hfModel.id;
  const slug = repoId.replace(/\//g, '--').toLowerCase();

  // Check if model already exists
  const existing = await db
    .prepare('SELECT id, downloads, likes FROM models WHERE hf_repo_id = ?')
    .bind(repoId)
    .first<{ id: number; downloads: number; likes: number }>();

  if (existing) {
    // Update existing model stats
    await db
      .prepare(
        `UPDATE models SET downloads = ?, likes = ?, updated_at = datetime('now') WHERE id = ?`,
      )
      .bind(hfModel.downloads || 0, hfModel.likes || 0, existing.id)
      .run();
    result.updated++;
    return;
  }

  // New model: fetch detailed info including files
  let detailedModel: HFModelSummary;
  try {
    const detailRes = await fetch(
      `https://huggingface.co/api/models/${repoId}?blobs=true`,
      { headers: { 'User-Agent': 'QuantaMrkt/1.0' } },
    );
    if (!detailRes.ok) {
      result.errors.push(`HF detail API error for ${repoId}: ${detailRes.status}`);
      return;
    }
    detailedModel = (await detailRes.json()) as HFModelSummary;
  } catch (err: any) {
    result.errors.push(`Detail fetch error for ${repoId}: ${err.message}`);
    return;
  }

  const [author, ...nameParts] = repoId.split('/');
  const modelName = nameParts.join('/') || repoId;
  const description = detailedModel.description || detailedModel.cardData?.description || null;
  const pipelineTag = detailedModel.pipeline_tag || hfModel.pipeline_tag || null;
  const license = detailedModel.cardData?.license || detailedModel.license || (hfModel as any).license || null;
  const downloads = detailedModel.downloads || hfModel.downloads || 0;
  const likes = detailedModel.likes || hfModel.likes || 0;

  // Build tags from pipeline_tag + model tags (cleaned and filtered)
  const tags = processHfTags(detailedModel.tags || [], pipelineTag);

  // Insert model
  const model = await db
    .prepare(
      `INSERT INTO models (slug, name, author, description, tags, license, framework, parameters, downloads, likes, verified, category, source_url, source_platform, hf_repo_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'huggingface', ?, datetime('now'), datetime('now'))
       RETURNING id, slug`,
    )
    .bind(
      slug,
      modelName,
      author,
      description,
      JSON.stringify(tags),
      license,
      pipelineTag,
      null,
      downloads,
      likes,
      pipelineTag,
      `https://huggingface.co/${repoId}`,
      repoId,
    )
    .first<{ id: number; slug: string }>();

  if (!model) {
    result.errors.push(`Failed to insert model ${repoId}`);
    return;
  }

  // Build file list from siblings
  const siblings = detailedModel.siblings || [];
  const files: { filename: string; hash: string; size: number }[] = siblings.map((f) => ({
    filename: f.rfilename || 'unknown',
    hash: f.lfs?.sha256 || 'pending-verification',
    size: f.lfs?.size || f.size || 0,
  }));

  // Generate manifest hash
  const fileHashes = files.map((f) => f.hash).join('|');
  const manifestHash = await sha256(`${repoId}|${new Date().toISOString()}|${fileHashes}`);

  // Generate PQC registry signature (stub)
  const sigPayload = `registry:${slug}:${manifestHash}`;
  const signatureHex = await sha256(sigPayload + ':ml-dsa-65');

  // Insert version
  const fileCount = files.length;
  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  const version = await db
    .prepare(
      `INSERT INTO model_versions (model_id, version, manifest_hash, file_count, total_size, r2_manifest_key, created_at)
       VALUES (?, 'v1.0.0', ?, ?, ?, ?, datetime('now'))
       RETURNING id`,
    )
    .bind(model.id, manifestHash, fileCount, totalSize, `manifests/${slug}/v1.0.0.json`)
    .first<{ id: number }>();

  if (version && files.length > 0) {
    // Batch insert files (max 50 at a time to avoid D1 limits)
    const batches: D1PreparedStatement[][] = [];
    let currentBatch: D1PreparedStatement[] = [];

    for (const f of files) {
      currentBatch.push(
        db
          .prepare('INSERT INTO model_files (version_id, filename, sha3_256_hash, size) VALUES (?, ?, ?, ?)')
          .bind(version.id, f.filename, f.hash, f.size),
      );
      if (currentBatch.length >= 50) {
        batches.push(currentBatch);
        currentBatch = [];
      }
    }
    if (currentBatch.length > 0) batches.push(currentBatch);

    for (const batch of batches) {
      await db.batch(batch);
    }
  }

  // Insert registry signature
  if (version) {
    await db
      .prepare(
        `INSERT INTO signatures (version_id, signer_did, algorithm, signature_hex, attestation_type, signed_at)
         VALUES (?, 'did:quantamrkt:registry:shield-v1', 'ML-DSA-65', ?, 'registry', datetime('now'))`,
      )
      .bind(version.id, signatureHex)
      .run();
  }

  // HNDL assessment
  let riskScore = 40;
  const sizeGB = totalSize / (1024 * 1024 * 1024);
  if (sizeGB > 100) riskScore += 30;
  else if (sizeGB > 10) riskScore += 20;
  else if (sizeGB > 1) riskScore += 10;

  if (downloads > 1_000_000) riskScore += 15;
  else if (downloads > 100_000) riskScore += 10;
  else if (downloads > 10_000) riskScore += 5;

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

  // Log to transparency log
  await appendLogEntry(db, {
    action: 'model:submitted',
    actor_did: 'did:quantamrkt:sync:huggingface',
    target_type: 'model',
    target_id: slug,
    metadata: {
      name: modelName,
      author,
      source: 'huggingface-sync',
      hf_repo_id: repoId,
      file_count: files.length,
      risk_level: riskLevel,
      risk_score: riskScore,
    },
  });

  result.created++;
}
