/**
 * Webex OAuth 2.0 Authentication Service
 *
 * Implements client-side PKCE flow for Webex OAuth.
 * The Webex access_token becomes the gateway's Bearer token directly.
 *
 * Flow:
 * 1. Frontend generates PKCE params and redirects to Webex authorize
 * 2. Webex redirects back with auth code
 * 3. Frontend sends code to backend /api/auth/token-exchange/webex
 *    (backend adds client_secret and exchanges with Webex)
 * 4. Frontend stores Webex access_token in localStorage
 * 5. All API requests include Authorization: Bearer <webex-token>
 */

// --- PKCE Utilities ---

function base64URLEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode.apply(null, Array.from(buffer)));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}

function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// --- Storage Keys ---

const STORAGE_KEYS = {
  ACCESS_TOKEN: 'webex_access_token',
  REFRESH_TOKEN: 'webex_refresh_token',
  TOKEN_EXPIRES_AT: 'webex_token_expires_at',
  USER_PROFILE: 'webex_user_profile',
  CODE_VERIFIER: 'webex_pkce_code_verifier',
  OAUTH_STATE: 'webex_oauth_state',
  REDIRECT_URI: 'webex_redirect_uri',
} as const;

// --- Types ---

export interface WebexUserProfile {
  id: string;
  displayName: string;
  emails: string[];
  orgId: string;
  avatar?: string;
  type?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

// --- Configuration ---

function getBaseURL(): string {
  const baseTag = document.querySelector('base');
  if (baseTag && baseTag.href) {
    const url = new URL(baseTag.href);
    return url.pathname.replace(/\/$/, '');
  }
  return '';
}

function getAuthConfig(): { clientId: string; authUrl: string; scopes: string } {
  // These are fetched from the backend config at runtime
  // For now, use env defaults that can be overridden
  return {
    clientId: (window as any).__WEBEX_CLIENT_ID__ || '',
    authUrl: (window as any).__WEBEX_AUTH_URL__ || 'https://webexapis.com/v1/authorize',
    scopes: (window as any).__WEBEX_SCOPES__ || 'spark:people_read',
  };
}

// --- Token Management ---

export function getAccessToken(): string | null {
  return localStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
}

export function getTokenExpiresAt(): number | null {
  const val = localStorage.getItem(STORAGE_KEYS.TOKEN_EXPIRES_AT);
  return val ? parseInt(val, 10) : null;
}

export function getUserProfile(): WebexUserProfile | null {
  const val = localStorage.getItem(STORAGE_KEYS.USER_PROFILE);
  if (val) {
    try {
      return JSON.parse(val);
    } catch {
      return null;
    }
  }
  return null;
}

export function isAuthenticated(): boolean {
  const token = getAccessToken();
  if (!token) return false;

  const expiresAt = getTokenExpiresAt();
  if (expiresAt && Date.now() > expiresAt) {
    // Token expired — caller should attempt refresh
    return false;
  }

  return true;
}

export function isTokenExpiringSoon(bufferMs: number = 5 * 60 * 1000): boolean {
  const expiresAt = getTokenExpiresAt();
  if (!expiresAt) return false; // No expiry info — assume token is still valid
  return Date.now() > expiresAt - bufferMs;
}

function storeTokens(data: TokenResponse): void {
  localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, data.access_token);

  if (data.refresh_token) {
    localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, data.refresh_token);
  }

  if (data.expires_in) {
    const expiresAt = Date.now() + data.expires_in * 1000;
    localStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, expiresAt.toString());
  }
}

function storeUserProfile(profile: WebexUserProfile): void {
  localStorage.setItem(STORAGE_KEYS.USER_PROFILE, JSON.stringify(profile));
}

function clearAuth(): void {
  Object.values(STORAGE_KEYS).forEach((key) => {
    localStorage.removeItem(key);
  });
  // Also clear sessionStorage PKCE params
  sessionStorage.removeItem(STORAGE_KEYS.CODE_VERIFIER);
  sessionStorage.removeItem(STORAGE_KEYS.OAUTH_STATE);
  sessionStorage.removeItem(STORAGE_KEYS.REDIRECT_URI);
}

// --- OAuth Flow ---

/**
 * Initiate Webex OAuth login with PKCE.
 * Redirects the browser to Webex authorization endpoint.
 */
export async function initiateWebexLogin(authConfig?: {
  clientId: string;
  authUrl: string;
  scopes: string;
}): Promise<void> {
  const config = authConfig || getAuthConfig();

  if (!config.clientId) {
    throw new Error('Webex client ID not configured');
  }

  // Generate PKCE params
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateState();

  // Build redirect URI (callback in the frontend app)
  const basePath = getBaseURL();
  const redirectUri = `${window.location.origin}${basePath}/auth/callback`;

  // Store PKCE params for the callback
  sessionStorage.setItem(STORAGE_KEYS.CODE_VERIFIER, codeVerifier);
  sessionStorage.setItem(STORAGE_KEYS.OAUTH_STATE, state);
  sessionStorage.setItem(STORAGE_KEYS.REDIRECT_URI, redirectUri);

  // Build authorization URL
  // Note: URLSearchParams encodes spaces as '+', but Webex requires '%20'.
  // We use encodeURIComponent for the scope parameter to get proper %20 encoding.
  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  const authorizationUrl = `${config.authUrl}?${params.toString()}&scope=${encodeURIComponent(config.scopes)}`;
  console.log('[WebexAuth] Redirecting to Webex authorization:', authorizationUrl);

  // Redirect to Webex
  window.location.href = authorizationUrl;
}

/**
 * Handle the OAuth callback after Webex redirects back.
 * Exchanges the authorization code for tokens via the backend.
 */
export async function handleOAuthCallback(
  code: string,
  state: string
): Promise<{ tokens: TokenResponse; profile: WebexUserProfile | null }> {
  // Validate state
  const storedState = sessionStorage.getItem(STORAGE_KEYS.OAUTH_STATE);
  if (state !== storedState) {
    clearAuth();
    throw new Error('OAuth state mismatch — possible CSRF attack');
  }

  // Retrieve PKCE code verifier
  const codeVerifier = sessionStorage.getItem(STORAGE_KEYS.CODE_VERIFIER);
  const redirectUri = sessionStorage.getItem(STORAGE_KEYS.REDIRECT_URI);

  // Clear PKCE params from sessionStorage
  sessionStorage.removeItem(STORAGE_KEYS.CODE_VERIFIER);
  sessionStorage.removeItem(STORAGE_KEYS.OAUTH_STATE);
  sessionStorage.removeItem(STORAGE_KEYS.REDIRECT_URI);

  if (!redirectUri) {
    throw new Error('Missing redirect_uri from session — please try logging in again');
  }

  // Exchange code for tokens via backend
  const basePath = getBaseURL();
  const response = await fetch(`${basePath}/api/auth/token-exchange/webex`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier || undefined,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Token exchange failed (${response.status})`);
  }

  const tokens: TokenResponse = await response.json();

  // Store tokens
  storeTokens(tokens);

  // Skip frontend profile fetch — the backend /api/auth/me endpoint
  // validates the token and returns user info server-side (avoids CORS
  // and uses the correct Webex API base URL for BTS/prod environments).
  return { tokens, profile: null };
}

/**
 * Fetch the authenticated user's Webex profile.
 */
async function fetchUserProfile(accessToken: string, apiBaseUrl: string = 'https://webexapis.com'): Promise<WebexUserProfile> {
  const response = await fetch(`${apiBaseUrl}/v1/people/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch Webex user profile (${response.status})`);
  }

  return response.json();
}

/**
 * Refresh the access token using the stored refresh token.
 * Returns the new token data, or null if refresh fails.
 */
export async function refreshAccessToken(): Promise<TokenResponse | null> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    console.warn('[WebexAuth] No refresh token available');
    return null;
  }

  try {
    const basePath = getBaseURL();
    const response = await fetch(`${basePath}/api/auth/refresh/webex`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      console.error('[WebexAuth] Token refresh failed:', response.status);
      // If refresh fails, clear auth state
      clearAuth();
      return null;
    }

    const tokens: TokenResponse = await response.json();
    storeTokens(tokens);
    console.log('[WebexAuth] Token refreshed successfully');
    return tokens;
  } catch (error) {
    console.error('[WebexAuth] Token refresh error:', error);
    clearAuth();
    return null;
  }
}

/**
 * Get a valid access token, refreshing if needed.
 * Returns null if no valid token is available.
 */
export async function getValidAccessToken(): Promise<string | null> {
  const token = getAccessToken();
  if (!token) return null;

  // If token is expiring soon, try to refresh
  if (isTokenExpiringSoon()) {
    console.log('[WebexAuth] Token expiring soon, attempting refresh...');
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      return refreshed.access_token;
    }
    return null;
  }

  return token;
}

/**
 * Sign out — clear all stored auth state.
 */
export function signOut(): void {
  clearAuth();
}

/**
 * Export for external use
 */
export default {
  initiateWebexLogin,
  handleOAuthCallback,
  refreshAccessToken,
  getValidAccessToken,
  getAccessToken,
  getRefreshToken,
  getUserProfile,
  isAuthenticated,
  isTokenExpiringSoon,
  signOut,
};
