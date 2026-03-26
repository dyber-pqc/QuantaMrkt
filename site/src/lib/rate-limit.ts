// Simple in-memory rate limiter (resets on worker restart, good enough for MVP)
const requests = new Map<string, { count: number; resetAt: number }>();

/**
 * Check if a request from the given key is within the rate limit.
 * Returns true if allowed, false if rate-limited.
 */
export function checkRateLimit(
  key: string,
  limit: number = 60,
  windowMs: number = 60000,
): boolean {
  const now = Date.now();
  const entry = requests.get(key);

  if (!entry || now > entry.resetAt) {
    requests.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  entry.count++;
  return entry.count <= limit;
}

/**
 * Helper to get a client identifier from a request.
 * Uses CF-Connecting-IP header (Cloudflare), falling back to X-Forwarded-For, then 'unknown'.
 */
export function getClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown'
  );
}

/**
 * Create a 429 Too Many Requests response.
 */
export function rateLimitResponse(): Response {
  return new Response(
    JSON.stringify({ error: 'Too many requests. Please try again later.' }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': '60',
      },
    },
  );
}
