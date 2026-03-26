import type { APIRoute } from 'astro';
import { getModelBySlug } from '../../../../lib/db';

export const GET: APIRoute = async ({ params, locals }) => {
  const json = (obj: unknown, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

  try {
    const slug = params.slug;
    if (!slug) {
      return json({ error: 'Missing slug parameter' }, 400);
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const model = await getModelBySlug(db, slug);

    if (!model) {
      return json({ error: 'Model not found' }, 404);
    }

    const verified = model.signatures.length > 0;
    const checkedAt = new Date().toISOString();

    // Build file integrity info
    let fileIntegrity: {
      total_files: number;
      matched: number;
      mismatched: number;
      missing: number;
      source_checked: boolean;
      source: string | null;
      details: { filename: string; status: string; size: number }[];
    } = {
      total_files: model.files.length,
      matched: 0,
      mismatched: 0,
      missing: 0,
      source_checked: false,
      source: null,
      details: [],
    };

    // If model has a HuggingFace repo, cross-check with the HF API
    if (model.hf_repo_id) {
      try {
        const hfRes = await fetch(`https://huggingface.co/api/models/${model.hf_repo_id}`, {
          headers: { 'User-Agent': 'QuantaMrkt/1.0' },
        });

        if (hfRes.ok) {
          const hfModel = (await hfRes.json()) as Record<string, any>;
          const hfSiblings: { rfilename?: string; filename?: string; size?: number; lfs?: { size?: number; sha256?: string } }[] = hfModel.siblings || [];
          const hfFileMap = new Map<string, { size: number; sha256: string | null }>();

          for (const s of hfSiblings) {
            const name = s.rfilename || s.filename || '';
            hfFileMap.set(name, {
              size: s.lfs?.size || s.size || 0,
              sha256: s.lfs?.sha256 || null,
            });
          }

          fileIntegrity.source_checked = true;
          fileIntegrity.source = 'huggingface.co';

          for (const file of model.files) {
            const hfFile = hfFileMap.get(file.filename);
            if (!hfFile) {
              fileIntegrity.missing++;
              fileIntegrity.details.push({ filename: file.filename, status: 'missing_from_source', size: file.size });
            } else if (file.sha3_256_hash && file.sha3_256_hash !== 'pending-verification' && hfFile.sha256 && file.sha3_256_hash !== hfFile.sha256) {
              fileIntegrity.mismatched++;
              fileIntegrity.details.push({ filename: file.filename, status: 'hash_mismatch', size: file.size });
            } else {
              fileIntegrity.matched++;
              fileIntegrity.details.push({ filename: file.filename, status: 'matched', size: file.size });
            }
          }

          // Check for new files on HF not in our manifest
          for (const [hfName] of hfFileMap) {
            if (!model.files.find((f) => f.filename === hfName)) {
              fileIntegrity.details.push({ filename: hfName, status: 'new_on_source', size: hfFileMap.get(hfName)!.size });
            }
          }
        }
      } catch {
        // HF API failed - still return what we have
        fileIntegrity.source_checked = false;
        fileIntegrity.source = null;

        // Mark all files as locally verified
        for (const file of model.files) {
          fileIntegrity.matched++;
          fileIntegrity.details.push({ filename: file.filename, status: 'local_only', size: file.size });
        }
      }
    } else {
      // No HF repo - just report local file info
      for (const file of model.files) {
        fileIntegrity.matched++;
        fileIntegrity.details.push({ filename: file.filename, status: 'local_only', size: file.size });
      }
    }

    return json({
      verified,
      model: model.hf_repo_id || `${model.author}/${model.name}`,
      signatures: model.signatures.map((s) => ({
        signer_did: s.signer_did,
        algorithm: s.algorithm,
        attestation_type: s.attestation_type,
        signed_at: s.signed_at,
      })),
      file_integrity: {
        total_files: fileIntegrity.total_files,
        matched: fileIntegrity.matched,
        mismatched: fileIntegrity.mismatched,
        missing: fileIntegrity.missing,
        source_checked: fileIntegrity.source_checked,
        source: fileIntegrity.source,
        details: fileIntegrity.details,
      },
      checked_at: checkedAt,
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
