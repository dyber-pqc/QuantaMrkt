import type { APIRoute } from 'astro';

const STATIC_PAGES = [
  '/',
  '/models',
  '/agents',
  '/explore',
  '/scan',
  '/download',
  '/chain',
  '/transparency',
  '/docs',
  '/features',
];

const SITE_URL = 'https://quantamrkt.com';

export const GET: APIRoute = async ({ locals }) => {
  const db = (locals as any).runtime?.env?.DB;

  const urls: { loc: string; changefreq: string; priority: string }[] = [];

  // Static pages
  for (const page of STATIC_PAGES) {
    urls.push({
      loc: `${SITE_URL}${page}`,
      changefreq: page === '/' ? 'daily' : 'weekly',
      priority: page === '/' ? '1.0' : '0.8',
    });
  }

  // Dynamic model pages
  if (db) {
    try {
      const modelsResult = await db
        .prepare('SELECT slug, updated_at FROM models ORDER BY updated_at DESC')
        .all<{ slug: string; updated_at: string }>();

      for (const model of modelsResult.results ?? []) {
        urls.push({
          loc: `${SITE_URL}/models/${model.slug}`,
          changefreq: 'weekly',
          priority: '0.7',
        });
      }
    } catch {
      // DB not available, skip dynamic pages
    }
  }

  // Dynamic agent pages
  if (db) {
    try {
      const agentsResult = await db
        .prepare('SELECT id FROM agents ORDER BY created_at DESC')
        .all<{ id: number }>();

      for (const agent of agentsResult.results ?? []) {
        urls.push({
          loc: `${SITE_URL}/agents/${agent.id}`,
          changefreq: 'monthly',
          priority: '0.5',
        });
      }
    } catch {
      // DB not available, skip dynamic pages
    }
  }

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
  .map(
    (u) => `  <url>
    <loc>${u.loc}</loc>
    <changefreq>${u.changefreq}</changefreq>
    <priority>${u.priority}</priority>
  </url>`,
  )
  .join('\n')}
</urlset>`;

  return new Response(xml, {
    status: 200,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
