import type { APIRoute } from 'astro';
import {
  exchangeCodeForToken,
  getGitHubUser,
  createSession,
  buildSessionCookie,
} from '../../../lib/auth';

export const GET: APIRoute = async ({ url, locals }) => {
  try {
    const code = url.searchParams.get('code');

    if (!code) {
      return Response.redirect(new URL('/?error=auth_failed', url.origin).toString(), 302);
    }

    const env = (locals as any).runtime?.env;
    const clientId = env?.GITHUB_CLIENT_ID;
    const clientSecret = env?.GITHUB_CLIENT_SECRET;
    const sessionSecret = env?.SESSION_SECRET;

    if (!clientId || !clientSecret || !sessionSecret) {
      return Response.redirect(new URL('/?error=missing_config', url.origin).toString(), 302);
    }

    // Exchange code for access token
    const accessToken = await exchangeCodeForToken(code, clientId, clientSecret);

    // Fetch GitHub user profile
    const user = await getGitHubUser(accessToken);

    // Create signed session cookie
    const sessionValue = await createSession(user, sessionSecret);
    const cookie = buildSessionCookie(sessionValue);

    return new Response(null, {
      status: 302,
      headers: {
        Location: '/dashboard',
        'Set-Cookie': cookie,
      },
    });
  } catch {
    const origin = url.origin || 'https://quantamrkt.com';
    return Response.redirect(`${origin}/?error=auth_failed`, 302);
  }
};
