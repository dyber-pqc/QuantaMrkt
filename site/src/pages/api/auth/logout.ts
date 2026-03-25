import type { APIRoute } from 'astro';
import { clearSessionCookie } from '../../../lib/auth';

export const GET: APIRoute = async () => {
  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': clearSessionCookie(),
    },
  });
};
