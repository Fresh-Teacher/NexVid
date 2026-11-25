import { NextRequest } from 'next/server';

const CLOUD_FEATURES_ENABLED = process.env.NEXT_PUBLIC_CLOUD_FEATURES_ENABLED === 'true';

function resolveCloudApiUrl(): string | null {
  if (!CLOUD_FEATURES_ENABLED) return null;
  const configured = (process.env.NEXT_PUBLIC_API_URL || process.env.API_URL || '').trim();
  if (!configured) return null;

  try {
    const url = new URL(configured);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return configured.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/**
 * Validates a cloud session by calling the external backend's /auth/me endpoint.
 * This should be used in server-side API routes to verify that the request comes from an authenticated user.
 */
export async function isValidCloudSession(
  request: Request | NextRequest,
  tokenOverride?: string,
): Promise<boolean> {
  const apiBase = resolveCloudApiUrl();
  if (!apiBase) return false;
  const incomingCookie = request.headers.get('cookie') || '';

  // Extract token from Authorization header or override
  let effectiveToken = tokenOverride;
  if (!effectiveToken) {
    const authHeader = request.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      effectiveToken = authHeader.substring(7);
    }
  }

  // Clean the token from common placeholder strings if they leaked into headers
  if (effectiveToken === 'undefined' || effectiveToken === 'null' || effectiveToken === '') {
    effectiveToken = undefined;
  }

  // If no token and no session cookie, session is invalid
  const hasSessionCookie = incomingCookie.includes('nexvid_session=');
  if (!effectiveToken && !hasSessionCookie) {
    return false;
  }

  try {
    const headers: Record<string, string> = {
      'Cache-Control': 'no-cache',
    };
    if (effectiveToken) {
      headers.Authorization = `Bearer ${effectiveToken}`;
    }
    if (incomingCookie) {
      headers.Cookie = incomingCookie;
    }

    const response = await fetch(`${apiBase}/auth/me`, {
      method: 'GET',
      headers,
      cache: 'no-store',
      // Short timeout to avoid hanging the edge function
      // @ts-ignore
      signal: AbortSignal.timeout(5000),
    });

    return response.ok;
  } catch (err) {
    console.error('[AuthServer] Session validation failed:', err);
    return false;
  }
}
