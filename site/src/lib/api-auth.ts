// API authentication helper — resolves session cookie or Bearer token to a D1 user

import type { DbUser } from './db';
import { getUserByGithubId, upsertUser } from './db';

const GITHUB_USER_URL = 'https://api.github.com/user';

/**
 * Resolve the authenticated user from either:
 *  1. Session cookie (locals.user set by middleware)
 *  2. Authorization: Bearer <github-token> header
 *
 * Returns the D1 user record, or null if unauthenticated.
 */
export async function getApiUser(
  locals: any,
  request?: Request,
): Promise<DbUser | null> {
  const db: D1Database | undefined = locals.runtime?.env?.DB;
  if (!db) return null;

  // 1. Try session-based auth (middleware already verified the cookie)
  const sessionUser = locals.user as { id: number; login: string; name: string | null; email: string | null; avatar_url: string } | undefined;
  if (sessionUser) {
    const dbUser = await getUserByGithubId(db, sessionUser.id);
    if (dbUser) return dbUser;
    // Session exists but user not in D1 yet — upsert
    return upsertUser(db, {
      github_id: sessionUser.id,
      login: sessionUser.login,
      name: sessionUser.name,
      email: sessionUser.email,
      avatar_url: sessionUser.avatar_url,
    });
  }

  // 2. Try Bearer token auth
  if (!request) return null;
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7).trim();
  if (!token) return null;

  try {
    const res = await fetch(GITHUB_USER_URL, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'QuantaMrkt',
      },
    });

    if (!res.ok) return null;

    const data = (await res.json()) as Record<string, unknown>;
    const githubId = data.id as number;
    const login = data.login as string;
    const name = (data.name as string) || null;
    const email = (data.email as string) || null;
    const avatarUrl = data.avatar_url as string;

    // Upsert into D1
    return upsertUser(db, {
      github_id: githubId,
      login,
      name,
      email,
      avatar_url: avatarUrl,
    });
  } catch {
    return null;
  }
}
