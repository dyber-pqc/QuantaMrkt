import type { APIRoute } from 'astro';
import { getModelBySlug } from '../../../../lib/db';

interface FileDetail {
  filename: string;
  status: string;
  size: number;
  size_match: boolean | null;
  exists_on_source: boolean | null;
  has_lfs_metadata: boolean | null;
  hash_verified: boolean | null;
  hash_note: string | null;
  source_size: number | null;
  source_sha256: string | null;
}

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
      new_on_source: number;
      source_checked: boolean;
      source: string | null;
      note: string;
      details: FileDetail[];
    } = {
      total_files: model.files.length,
      matched: 0,
      mismatched: 0,
      missing: 0,
      new_on_source: 0,
      source_checked: false,
      source: null,
      note: '',
      details: [],
    };

    // If model has a HuggingFace repo, cross-check with the HF API
    if (model.hf_repo_id) {
      try {
        const hfRes = await fetch(
          `https://huggingface.co/api/models/${model.hf_repo_id}?blobs=true`,
          { headers: { 'User-Agent': 'QuantaMrkt/1.0' } },
        );

        if (hfRes.ok) {
          const hfModel = (await hfRes.json()) as Record<string, any>;
          const hfSiblings: {
            rfilename?: string;
            filename?: string;
            size?: number;
            lfs?: { size?: number; sha256?: string };
          }[] = hfModel.siblings || [];

          const hfFileMap = new Map<
            string,
            { size: number; sha256: string | null; hasLfs: boolean }
          >();

          for (const s of hfSiblings) {
            const name = s.rfilename || s.filename || '';
            hfFileMap.set(name, {
              size: s.lfs?.size || s.size || 0,
              sha256: s.lfs?.sha256 || null,
              hasLfs: !!(s.lfs && s.lfs.sha256),
            });
          }

          fileIntegrity.source_checked = true;
          fileIntegrity.source = 'huggingface.co';
          fileIntegrity.note =
            'HuggingFace uses SHA-256 for LFS blobs; we store SHA3-256. ' +
            'Hash comparison across algorithms is not possible. ' +
            'Size and existence checks are performed. ' +
            'For true hash verification, run `quantumshield verify --deep` locally.';

          for (const file of model.files) {
            const hfFile = hfFileMap.get(file.filename);

            if (!hfFile) {
              // File is in our manifest but missing on HuggingFace
              fileIntegrity.missing++;
              fileIntegrity.details.push({
                filename: file.filename,
                status: 'missing_from_source',
                size: file.size,
                size_match: null,
                exists_on_source: false,
                has_lfs_metadata: null,
                hash_verified: null,
                hash_note: 'File not found on source',
                source_size: null,
                source_sha256: null,
              });
            } else {
              // File exists on HF — check size
              const sizeMatch = file.size > 0 && hfFile.size > 0 && file.size === hfFile.size;
              const sizeUnavailable = file.size === 0 || hfFile.size === 0;

              if (sizeMatch || sizeUnavailable) {
                fileIntegrity.matched++;
                fileIntegrity.details.push({
                  filename: file.filename,
                  status: 'present_on_source',
                  size: file.size,
                  size_match: sizeUnavailable ? null : true,
                  exists_on_source: true,
                  has_lfs_metadata: hfFile.hasLfs,
                  hash_verified: false,
                  hash_note: hfFile.hasLfs
                    ? 'Cannot cross-verify: source uses SHA-256, manifest uses SHA3-256. Run `quantumshield verify --deep` locally.'
                    : 'No LFS hash available on source. Run `quantumshield verify --deep` locally.',
                  source_size: hfFile.size,
                  source_sha256: hfFile.sha256,
                });
              } else {
                // Size mismatch — likely the file was modified
                fileIntegrity.mismatched++;
                fileIntegrity.details.push({
                  filename: file.filename,
                  status: 'size_mismatch',
                  size: file.size,
                  size_match: false,
                  exists_on_source: true,
                  has_lfs_metadata: hfFile.hasLfs,
                  hash_verified: false,
                  hash_note: `Size mismatch: manifest=${file.size}, source=${hfFile.size}. File may have been modified.`,
                  source_size: hfFile.size,
                  source_sha256: hfFile.sha256,
                });
              }
            }
          }

          // Check for new files on HF not in our manifest
          for (const [hfName, hfFile] of hfFileMap) {
            if (!model.files.find((f) => f.filename === hfName)) {
              fileIntegrity.new_on_source++;
              fileIntegrity.details.push({
                filename: hfName,
                status: 'new_on_source',
                size: hfFile.size,
                size_match: null,
                exists_on_source: true,
                has_lfs_metadata: hfFile.hasLfs,
                hash_verified: null,
                hash_note: 'File exists on source but not in signed manifest. May have been added after signing.',
                source_size: hfFile.size,
                source_sha256: hfFile.sha256,
              });
            }
          }
        } else {
          // HF API returned an error status
          fileIntegrity.source_checked = false;
          fileIntegrity.source = null;
          fileIntegrity.note = `HuggingFace API returned status ${hfRes.status}. Could not verify against source.`;

          for (const file of model.files) {
            fileIntegrity.matched++;
            fileIntegrity.details.push({
              filename: file.filename,
              status: 'local_only',
              size: file.size,
              size_match: null,
              exists_on_source: null,
              has_lfs_metadata: null,
              hash_verified: null,
              hash_note: 'Source unavailable. Run `quantumshield verify --deep` locally.',
              source_size: null,
              source_sha256: null,
            });
          }
        }
      } catch {
        // HF API call failed entirely
        fileIntegrity.source_checked = false;
        fileIntegrity.source = null;
        fileIntegrity.note = 'HuggingFace API unreachable. Could not verify against source.';

        for (const file of model.files) {
          fileIntegrity.matched++;
          fileIntegrity.details.push({
            filename: file.filename,
            status: 'local_only',
            size: file.size,
            size_match: null,
            exists_on_source: null,
            has_lfs_metadata: null,
            hash_verified: null,
            hash_note: 'Source unreachable. Run `quantumshield verify --deep` locally.',
            source_size: null,
            source_sha256: null,
          });
        }
      }
    } else {
      // No HF repo — just report local file info
      fileIntegrity.note = 'No source repository configured. Only local manifest data available.';

      for (const file of model.files) {
        fileIntegrity.matched++;
        fileIntegrity.details.push({
          filename: file.filename,
          status: 'local_only',
          size: file.size,
          size_match: null,
          exists_on_source: null,
          has_lfs_metadata: null,
          hash_verified: null,
          hash_note: 'No source repository configured.',
          source_size: null,
          source_sha256: null,
        });
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
      file_integrity: fileIntegrity,
      checked_at: checkedAt,
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
