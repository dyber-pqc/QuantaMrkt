// GitHub OAuth + HMAC session management for Cloudflare Workers

export interface User {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
  tier: 'free' | 'pro' | 'team' | 'enterprise';
}

const COOKIE_NAME = 'qm_session';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_USER_URL = 'https://api.github.com/user';
const REDIRECT_URI = 'https://quantamrkt.com/api/auth/callback';

/**
 * Build the GitHub OAuth authorization URL.
 */
export function getGitHubAuthUrl(clientId: string): string {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'read:user user:email',
  });
  return `${GITHUB_AUTHORIZE_URL}?${params.toString()}`;
}

/**
 * Exchange an authorization code for an access token.
 */
export async function exchangeCodeForToken(
  code: string,
  clientId: string,
  clientSecret: string,
): Promise<string> {
  const res = await fetch(GITHUB_TOKEN_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: REDIRECT_URI,
    }),
  });

  if (!res.ok) {
    throw new Error(`GitHub token exchange failed: ${res.status}`);
  }

  const data = (await res.json()) as { access_token?: string; error?: string; error_description?: string };

  if (data.error || !data.access_token) {
    throw new Error(data.error_description || data.error || 'No access token returned');
  }

  return data.access_token;
}

/**
 * Fetch the authenticated GitHub user's profile.
 */
export async function getGitHubUser(token: string): Promise<User> {
  const res = await fetch(GITHUB_USER_URL, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'QuantaMrkt',
    },
  });

  if (!res.ok) {
    throw new Error(`GitHub user fetch failed: ${res.status}`);
  }

  const data = (await res.json()) as Record<string, unknown>;

  return {
    id: data.id as number,
    login: data.login as string,
    name: (data.name as string) || null,
    email: (data.email as string) || null,
    avatar_url: data.avatar_url as string,
    tier: 'free',
  };
}

// ---- HMAC-based session cookie helpers (Web Crypto API) ----

function encodeBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function hmacSign(payload: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return encodeBase64Url(sig);
}

async function hmacVerify(payload: string, signature: string, secret: string): Promise<boolean> {
  const expected = await hmacSign(payload, secret);
  // Constant-time-ish comparison (both are base64url strings of same HMAC length)
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Create a signed session cookie value from a User object.
 * Format: base64url(JSON) + "." + base64url(HMAC-SHA256)
 */
export async function createSession(user: User, sessionSecret: string): Promise<string> {
  const payload = JSON.stringify({
    id: user.id,
    login: user.login,
    name: user.name,
    email: user.email,
    avatar_url: user.avatar_url,
    tier: user.tier,
    iat: Math.floor(Date.now() / 1000),
  });

  const encodedPayload = encodeBase64Url(new TextEncoder().encode(payload));
  const signature = await hmacSign(encodedPayload, sessionSecret);

  return `${encodedPayload}.${signature}`;
}

/**
 * Parse a cookie header and verify the session cookie.
 * Returns the User or null if invalid / missing.
 */
export async function getSession(
  cookieHeader: string | null | undefined,
  sessionSecret: string,
): Promise<User | null> {
  if (!cookieHeader) return null;

  // Parse cookies
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map((c) => {
      const [key, ...rest] = c.trim().split('=');
      return [key, rest.join('=')];
    }),
  );

  const token = cookies[COOKIE_NAME];
  if (!token) return null;

  const dotIndex = token.lastIndexOf('.');
  if (dotIndex === -1) return null;

  const encodedPayload = token.substring(0, dotIndex);
  const signature = token.substring(dotIndex + 1);

  try {
    const valid = await hmacVerify(encodedPayload, signature, sessionSecret);
    if (!valid) return null;

    const jsonBytes = decodeBase64Url(encodedPayload);
    const payload = JSON.parse(new TextDecoder().decode(jsonBytes)) as Record<string, unknown>;

    // Check expiry (7 days)
    const iat = payload.iat as number;
    if (Date.now() / 1000 - iat > COOKIE_MAX_AGE) return null;

    return {
      id: payload.id as number,
      login: payload.login as string,
      name: (payload.name as string) || null,
      email: (payload.email as string) || null,
      avatar_url: payload.avatar_url as string,
      tier: (payload.tier as User['tier']) || 'free',
    };
  } catch {
    return null;
  }
}

/**
 * Build the Set-Cookie header value for the session cookie.
 */
export function buildSessionCookie(value: string): string {
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${COOKIE_MAX_AGE}`;
}

/**
 * Build the Set-Cookie header value that clears the session cookie.
 */
export function clearSessionCookie(): string {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
