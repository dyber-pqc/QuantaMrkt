import { defineMiddleware } from 'astro:middleware';
import { getSession } from './lib/auth';

/**
 * Routes that require authentication (anything under /dashboard).
 * Public routes: /, /features, /pricing, /docs/*, /api/*, and all static assets.
 */
function requiresAuth(pathname: string): boolean {
  return pathname.startsWith('/dashboard');
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname } = context.url;

  // Skip auth check for public routes
  if (!requiresAuth(pathname)) {
    // Still try to attach user for layouts that conditionally show auth state
    try {
      const env = (context.locals as any).runtime?.env;
      const sessionSecret = env?.SESSION_SECRET;
      if (sessionSecret) {
        const cookieHeader = context.request.headers.get('cookie');
        const user = await getSession(cookieHeader, sessionSecret);
        if (user) {
          (context.locals as any).user = user;
        }
      }
    } catch {
      // Ignore errors on public routes
    }
    return next();
  }

  // Protected route: verify session
  try {
    const env = (context.locals as any).runtime?.env;
    const sessionSecret = env?.SESSION_SECRET;

    if (!sessionSecret) {
      return context.redirect('/api/auth/login', 302);
    }

    const cookieHeader = context.request.headers.get('cookie');
    const user = await getSession(cookieHeader, sessionSecret);

    if (!user) {
      return context.redirect('/api/auth/login', 302);
    }

    // Attach user to locals so pages/layouts can access it
    (context.locals as any).user = user;
    return next();
  } catch {
    return context.redirect('/api/auth/login', 302);
  }
});
