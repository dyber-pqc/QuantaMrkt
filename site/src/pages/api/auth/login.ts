import type { APIRoute } from 'astro';
import { getGitHubAuthUrl } from '../../../lib/auth';

export const GET: APIRoute = async ({ locals, redirect }) => {
  try {
    const env = (locals as any).runtime?.env;
    const clientId = env?.GITHUB_CLIENT_ID;

    if (!clientId) {
      return redirect('/?error=missing_config', 302);
    }

    const authUrl = getGitHubAuthUrl(clientId);
    return redirect(authUrl, 302);
  } catch {
    return redirect('/?error=auth_failed', 302);
  }
};
