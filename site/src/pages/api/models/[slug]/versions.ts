import type { APIRoute } from 'astro';
import { getModelBySlug, createVersion, logActivity } from '../../../../lib/db';
import { getApiUser } from '../../../../lib/api-auth';
import { appendLogEntry } from '../../../../lib/transparency';

export const POST: APIRoute = async ({ params, request, locals }) => {
  try {
    const user = await getApiUser(locals, request);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const slug = params.slug;
    if (!slug) {
      return new Response(JSON.stringify({ error: 'Missing slug parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const db = (locals as any).runtime.env.DB as D1Database;
    const model = await getModelBySlug(db, slug);

    if (!model) {
      return new Response(JSON.stringify({ error: 'Model not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const body = await request.json() as Record<string, any>;
    const { version, manifestHash, files, signatures } = body;

    if (!version || !manifestHash) {
      return new Response(JSON.stringify({ error: 'Missing required fields: version, manifestHash' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Store manifest in R2
    const r2: R2Bucket | undefined = (locals as any).runtime.env.MANIFESTS;
    const r2Key = `manifests/${slug}/${version}.json`;

    if (r2) {
      await r2.put(r2Key, JSON.stringify(body), {
        httpMetadata: { contentType: 'application/json' },
      });
    }

    const versionRecord = await createVersion(db, model.id, {
      version,
      manifestHash,
      r2ManifestKey: r2Key,
      files: files || [],
      signatures: signatures || [],
    });

    await logActivity(db, {
      userId: user.id,
      action: 'version.create',
      target: `${slug}@${version}`,
      details: `Published version ${version} for ${model.name}`,
    });

    // Append to transparency log: manifest push
    await appendLogEntry(db, {
      action: 'manifest:pushed',
      target_type: 'manifest',
      target_id: `${slug}@${version}`,
      metadata: { manifestHash, fileCount: (files || []).length },
    });

    // Log each signature
    if (signatures && signatures.length > 0) {
      for (const sig of signatures) {
        await appendLogEntry(db, {
          action: 'model:signed',
          actor_did: sig.signerDid,
          target_type: 'model',
          target_id: slug,
          metadata: { version, algorithm: sig.algorithm, attestationType: sig.attestationType || null },
        });
      }
    }

    return new Response(JSON.stringify(versionRecord), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message || 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
