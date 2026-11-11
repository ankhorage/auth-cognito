import type {
  AuthOAuthCompletionResult,
  AuthOAuthError,
  AuthOAuthStartResult,
  AuthSession,
  CompleteOAuthAuthorizationInput,
  StartOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';

import type { CognitoAuthConfig, CognitoJwtVerifier } from '../../../../types/cognito.js';

const DEFAULT_AUTHORIZATION_TTL_MS = 10 * 60 * 1000;
const RESERVED_PARAMETERS = new Set([
  'response_type', 'client_id', 'redirect_uri', 'scope',
  'state', 'nonce', 'code_challenge', 'code_challenge_method', 'identity_provider',
]);

/*** Provide single-use PKCE OAuth operations through Cognito's HTTPS authorization server. */
export function createCognitoOAuthHandlers(
  config: CognitoAuthConfig,
  verifyJwt: CognitoJwtVerifier,
) {
  return {
    start: async (input: StartOAuthAuthorizationInput): Promise<AuthOAuthStartResult> => {
      const domain = authorizationDomain(config.public.hostedDomain);
      if (!domain) return startFailure('provider_misconfigured', input.provider);
      if (!config.public.redirectUris.includes(input.redirectUri)) {
        return startFailure('invalid_redirect_uri', input.provider);
      }
      const provider = resolveProvider(config, input.provider);
      if (provider === null) return startFailure('provider_disabled', input.provider);
      const attemptId = (config.createAttemptId ?? crypto.randomUUID)();
      const state = randomToken();
      const nonce = randomToken();
      const verifier = randomToken();
      try {
        const codeChallenge = await pkceChallenge(verifier);
        const url = new URL('/oauth2/authorize', domain);
        url.searchParams.set('client_id', config.public.clientId);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('redirect_uri', input.redirectUri);
        url.searchParams.set('scope', [...new Set(['openid', ...(input.scopes ?? config.public.scopes ?? [])])].join(' '));
        url.searchParams.set('state', state);
        url.searchParams.set('nonce', nonce);
        url.searchParams.set('code_challenge_method', 'S256');
        url.searchParams.set('code_challenge', codeChallenge);
        if (provider !== '') url.searchParams.set('identity_provider', provider);
        for (const [key, value] of Object.entries(input.queryParams ?? {})) {
          if (!RESERVED_PARAMETERS.has(key)) url.searchParams.set(key, value);
        }
        await config.authorizationAttempts.create({
          attemptId,
          redirectUri: input.redirectUri,
          provider: input.provider,
          state,
          nonce,
          codeVerifier: verifier,
          expiresAt: now(config) + (config.authorizationAttemptTtlMs ?? DEFAULT_AUTHORIZATION_TTL_MS),
        });
        return {
          ok: true,
          data: {
            attemptId,
            provider: input.provider,
            authorizationUrl: url.toString(),
            redirectUri: input.redirectUri,
          },
        };
      } catch {
        return startFailure('authorization_failed', input.provider);
      }
    },
    complete: async (input: CompleteOAuthAuthorizationInput): Promise<AuthOAuthCompletionResult> => {
      const currentTime = now(config);
      const attempt = await config.authorizationAttempts.consume(input.attemptId, currentTime).catch(() => null);
      if (!attempt || attempt.expiresAt <= currentTime) {
        return completeFailure('authorization_attempt_not_found', 'callback');
      }
      if (input.response.type === 'cancelled') {
        return {
          ok: false,
          status: 'cancelled',
          provider: attempt.provider,
          reason: input.response.reason,
        };
      }
      if (input.response.type === 'error') {
        return completeFailure('provider_error', 'transport', attempt.provider);
      }
      const callback = parseCallback(input.response.url, attempt.redirectUri);
      if (!callback) return completeFailure('invalid_callback', 'callback', attempt.provider);
      if (callback.state !== attempt.state) {
        return completeFailure('state_mismatch', 'callback', attempt.provider);
      }
      if (callback.error || !callback.code) {
        return completeFailure('invalid_callback', 'callback', attempt.provider);
      }
      const domain = authorizationDomain(config.public.hostedDomain);
      if (!domain) return completeFailure('provider_misconfigured', 'exchange', attempt.provider);
      try {
        const body = new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: config.public.clientId,
          code: callback.code,
          redirect_uri: attempt.redirectUri,
          code_verifier: attempt.codeVerifier,
        });
        const response = await (config.http ?? fetch)(
          new URL('/oauth2/token', domain).toString(),
          {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body,
          },
        );
        if (!response.ok) return completeFailure('code_exchange_failed', 'exchange', attempt.provider);
        const tokens: unknown = await response.json();
        if (!isTokenResponse(tokens)) {
          return completeFailure('invalid_callback', 'session', attempt.provider);
        }
        const [access, identity] = await Promise.all([
          verifyJwt(tokens.access_token, 'access'),
          verifyJwt(tokens.id_token, 'id'),
        ]);
        if (!access.sub || access.sub !== identity.sub || identity.nonce !== attempt.nonce) {
          return completeFailure('invalid_callback', 'session', attempt.provider);
        }
        const session: AuthSession = {
          accessToken: tokens.access_token,
          ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
          expiresAt: now(config) + tokens.expires_in * 1000,
          tokenType: 'Bearer',
          user: { id: access.sub },
        };
        await config.sessions.write(session);
        return {
          ok: true,
          status: 'authenticated',
          provider: attempt.provider,
          session,
        };
      } catch {
        return completeFailure('code_exchange_failed', 'exchange', attempt.provider);
      }
    },
  };
}

/*** Restrict Cognito authorization to a configured HTTPS endpoint. */
function authorizationDomain(value: string): URL | null {
  try {
    const domain = new URL(value);
    return domain.protocol === 'https:' && !domain.username && !domain.password
      && domain.pathname === '/' && !domain.search && !domain.hash ? domain : null;
  } catch {
    return null;
  }
}

/*** Never accept an unconfigured federated identity provider or arbitrary identity_provider. */
function resolveProvider(config: CognitoAuthConfig, provider: string): string | null {
  if (provider === 'cognito') return '';
  return config.public.oauthProviders?.[provider] ?? null;
}

/*** Generate a cryptographically random base64url PKCE verifier, state, or nonce. */
function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

/*** Bind the authorization code to its originating client with an S256 challenge. */
async function pkceChallenge(verifier: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return btoa(String.fromCharCode(...digest))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

/*** Validate callback location and reject duplicate or missing OAuth parameters. */
function parseCallback(url: string, redirectUri: string) {
  try {
    const actual = new URL(url);
    const expected = new URL(redirectUri);
    if (actual.protocol !== expected.protocol || actual.host !== expected.host || actual.pathname !== expected.pathname) return null;
    const state = actual.searchParams.getAll('state');
    const codes = actual.searchParams.getAll('code');
    if (state.length !== 1 || codes.length > 1) return null;
    return { state: state[0], code: codes[0], error: actual.searchParams.get('error') };
  } catch {
    return null;
  }
}

/*** Decode the untrusted token response without accepting incomplete or malformed sessions. */
function isTokenResponse(value: unknown): value is {
  readonly access_token: string;
  readonly id_token: string;
  readonly refresh_token?: string;
  readonly expires_in: number;
} {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  if (!('access_token' in value) || typeof value.access_token !== 'string') return false;
  if (!('id_token' in value) || typeof value.id_token !== 'string') return false;
  if (!('expires_in' in value) || typeof value.expires_in !== 'number'
      || !Number.isFinite(value.expires_in) || value.expires_in <= 0) return false;
  return !('refresh_token' in value) || typeof value.refresh_token === 'string';
}

/*** Produce an OAuth start error with no callback, code, or token details. */
function startFailure(code: AuthOAuthError['code'], provider: string): AuthOAuthStartResult {
  return { ok: false, error: oauthError(code, 'start', provider) };
}

/*** Produce an OAuth completion error with no sensitive provider payload. */
function completeFailure(
  code: AuthOAuthError['code'],
  stage: AuthOAuthError['stage'],
  provider?: string,
): AuthOAuthCompletionResult {
  return { ok: false, status: 'error', error: oauthError(code, stage, provider) };
}

/*** Normalize Cognito OAuth errors using released portable Auth contracts. */
function oauthError(
  code: AuthOAuthError['code'],
  stage: AuthOAuthError['stage'],
  provider?: string,
): AuthOAuthError {
  return {
    code,
    stage,
    recoverable: false,
    message: 'Cognito authorization failed.',
    ...(provider ? { provider } : {}),
  };
}

/*** Resolve the injected deterministic clock for durable OAuth attempt expiration. */
function now(config: CognitoAuthConfig): number {
  return (config.now ?? Date.now)();
}
