import type { AuthSession } from '@ankhorage/contracts/auth';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { expect, test } from 'bun:test';

import { createCognitoAuthAdapter } from './index.js';
import type {
  CognitoAuthConfig,
  CognitoAuthorizationAttempt,
  CognitoAuthorizationAttemptStore,
  CognitoSessionStore,
} from './types/cognito.js';

/*** Provide an atomic durable-attempt-shaped fake for behavior tests. */
function createAttemptStore(): CognitoAuthorizationAttemptStore {
  const attempts = new Map<string, CognitoAuthorizationAttempt>();
  return {
    create: (attempt) => {
      if (attempts.has(attempt.attemptId)) return Promise.reject(new Error('duplicate attempt'));
      attempts.set(attempt.attemptId, attempt);
      return Promise.resolve();
    },
    consume: (id, now) => {
      const attempt = attempts.get(id) ?? null;
      attempts.delete(id);
      return Promise.resolve(attempt && attempt.expiresAt > now ? attempt : null);
    },
  };
}

/*** Retain the test session only inside an injected consumer-owned store. */
function createSessionStore(): CognitoSessionStore {
  const state: { session: AuthSession | null } = { session: null };
  return {
    read: () => Promise.resolve(state.session),
    write: (session) => {
      state.session = session;
      return Promise.resolve();
    },
    clear: () => {
      state.session = null;
      return Promise.resolve();
    },
  };
}

/*** Create public User Pool configuration with no live Cognito I/O. */
function createConfig(overrides: Partial<CognitoAuthConfig> = {}): CognitoAuthConfig {
  return {
    public: {
      region: 'eu-central-1',
      userPoolId: 'eu-central-1_example',
      clientId: 'public-client',
      hostedDomain: 'https://login.example.test',
      redirectUris: ['https://grossmeister.example.test/callback'],
      oauthProviders: { google: 'Google' },
    },
    client: new CognitoIdentityProviderClient({
      region: 'eu-central-1',
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    }),
    sessions: createSessionStore(),
    authorizationAttempts: createAttemptStore(),
    verifyJwt: () => Promise.resolve({ sub: 'player-1' }),
    createAttemptId: () => 'attempt-1',
    now: () => 1_000,
    ...overrides,
  };
}

/*** Resolve the exact callback URL and verify PKCE information is present. */
async function startAuthorization(config: CognitoAuthConfig) {
  const adapter = createCognitoAuthAdapter(config);
  const started = await adapter.startAuthorization({
    provider: 'google',
    redirectUri: 'https://grossmeister.example.test/callback',
  });
  if (!started.ok) throw new Error('Expected Cognito OAuth authorization to start.');
  return { adapter, started, url: new URL(started.data.authorizationUrl) };
}

test('starts brokered Cognito authorization with strong PKCE and a one-time attempt', async () => {
  const { started, url } = await startAuthorization(createConfig());
  expect(started.data.provider).toBe('google');
  expect(url.pathname).toBe('/oauth2/authorize');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('identity_provider')).toBe('Google');
  expect(url.searchParams.get('code_challenge')?.length).toBe(43);
  expect(url.searchParams.get('nonce')?.length).toBe(43);
  expect(url.searchParams.get('state')?.length).toBe(43);
});

test('rejects unregistered callback URLs and unconfigured federation providers', async () => {
  const adapter = createCognitoAuthAdapter(createConfig());
  expect(
    await adapter.startAuthorization({
      provider: 'google',
      redirectUri: 'https://wrong.example.test/callback',
    }),
  ).toMatchObject({ ok: false, error: { code: 'invalid_redirect_uri' } });
  expect(
    await adapter.startAuthorization({
      provider: 'unapproved',
      redirectUri: 'https://grossmeister.example.test/callback',
    }),
  ).toMatchObject({ ok: false, error: { code: 'provider_disabled' } });
});

/*** Simulate the Cognito token exchange without bypassing the real PKCE request body. */
function createSuccessfulTokenResponse(calls: string[]): typeof fetch {
  return (_url, init) => {
    calls.push(init?.body instanceof URLSearchParams ? init.body.toString() : '');
    return Promise.resolve(
      new Response(
        JSON.stringify({
          access_token: 'access-test',
          id_token: 'id-test',
          refresh_token: 'refresh-test',
          expires_in: 3600,
        }),
        { status: 200 },
      ),
    );
  };
}

test('completes Cognito PKCE once with verified access and nonce-bound ID JWTs', async () => {
  const nonceValue: { current: string | null } = { current: null };
  const httpCalls: string[] = [];
  const config = createConfig({
    verifyJwt: (_token, use) =>
      Promise.resolve({
        sub: 'player-1',
        ...(use === 'id' && nonceValue.current ? { nonce: nonceValue.current } : {}),
      }),
    http: createSuccessfulTokenResponse(httpCalls),
  });
  const { adapter, started, url } = await startAuthorization(config);
  nonceValue.current = url.searchParams.get('nonce');
  const callback =
    'https://grossmeister.example.test/callback?code=auth-code&state=' +
    encodeURIComponent(url.searchParams.get('state') ?? '');
  const completed = await adapter.completeAuthorization({
    attemptId: started.data.attemptId,
    response: { type: 'callback', url: callback },
  });
  expect(completed).toMatchObject({
    ok: true,
    status: 'authenticated',
    session: { user: { id: 'player-1' }, accessToken: 'access-test' },
  });
  expect(httpCalls).toHaveLength(1);
  expect(httpCalls[0]).toContain('code_verifier=');
  expect(await adapter.getSession()).toMatchObject({
    ok: true,
    data: { user: { id: 'player-1' } },
  });
  const replay = await adapter.completeAuthorization({
    attemptId: started.data.attemptId,
    response: { type: 'callback', url: callback },
  });
  expect(replay).toMatchObject({
    ok: false,
    status: 'error',
    error: { code: 'authorization_attempt_not_found' },
  });
  expect(httpCalls).toHaveLength(1);
});

test('rejects state mismatch before invoking the Cognito token endpoint', async () => {
  const calls: string[] = [];
  const config = createConfig({
    http: (url) => {
      calls.push(typeof url === 'string' ? url : url instanceof URL ? url.href : url.url);
      return Promise.resolve(new Response('denied', { status: 400 }));
    },
  });
  const { adapter } = await startAuthorization(config);
  const mismatch = await adapter.completeAuthorization({
    attemptId: 'attempt-1',
    response: {
      type: 'callback',
      url: 'https://grossmeister.example.test/callback?code=code&state=attacker',
    },
  });
  expect(mismatch).toMatchObject({ ok: false, error: { code: 'state_mismatch' } });
  expect(calls).toEqual([]);
});

test('rejects ID tokens without the expected OIDC nonce', async () => {
  const config = createConfig({
    http: () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            access_token: 'access-test',
            id_token: 'id-test',
            expires_in: 3600,
          }),
        ),
      ),
  });
  const { adapter, started, url } = await startAuthorization(config);
  const result = await adapter.completeAuthorization({
    attemptId: started.data.attemptId,
    response: {
      type: 'callback',
      url:
        'https://grossmeister.example.test/callback?code=test&state=' +
        encodeURIComponent(url.searchParams.get('state') ?? ''),
    },
  });
  expect(result).toMatchObject({ ok: false, status: 'error', error: { code: 'invalid_callback' } });
});

test('rejects missing-password sign-in without contacting AWS', async () => {
  const adapter = createCognitoAuthAdapter(createConfig());
  const result = await adapter.signIn({ identifier: { kind: 'email', value: 'test@example.org' } });
  expect(result).toMatchObject({ ok: false, error: { code: 'password_required' } });
});

test('rejects persisted sessions with a subject that does not match the verified token', async () => {
  const sessions = createSessionStore();
  await sessions.write({ accessToken: 'signed-token', user: { id: 'different-user' } });
  const adapter = createCognitoAuthAdapter(createConfig({ sessions }));
  expect(await adapter.getSession()).toMatchObject({
    ok: false,
    error: { code: 'invalid_session' },
  });
});

/*** Read only the typed AWS JSON command target from an untrusted SDK request. */
function readCognitoCommandName(request: unknown): string {
  if (typeof request !== 'object' || request === null || !('headers' in request)) {
    return '';
  }
  const headers = request.headers;
  if (typeof headers !== 'object' || headers === null || !('x-amz-target' in headers)) {
    return '';
  }
  return typeof headers['x-amz-target'] === 'string' ? headers['x-amz-target'] : '';
}

/*** Exercise real AWS SDK command serialization with a deterministic local request handler. */
function createAwsSdkTestClient() {
  const commands: string[] = [];
  const client = new CognitoIdentityProviderClient({
    region: 'eu-central-1',
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    requestHandler: {
      handle: (request: unknown) => {
        const target = readCognitoCommandName(request);
        commands.push(target);
        const result =
          target.endsWith('.SignUp')
            ? { UserSub: 'player-1', UserConfirmed: false }
            : target.endsWith('.InitiateAuth') || target.endsWith('.GetTokensFromRefreshToken')
              ? {
                  AuthenticationResult: {
                    AccessToken: 'access-token',
                    ExpiresIn: 3600,
                    RefreshToken: 'refresh-token',
                    TokenType: 'Bearer',
                  },
                }
              : {};
        return Promise.resolve({
          response: {
            statusCode: 200,
            headers: { 'content-type': 'application/x-amz-json-1.1' },
            body: new TextEncoder().encode(JSON.stringify(result)),
          },
        });
      },
    },
  });
  return { client, commands };
}

test('performs real SDK signup, sign-in, refresh and sign-out through injected transport', async () => {
  const { client, commands } = createAwsSdkTestClient();
  const sessions = createSessionStore();
  const adapter = createCognitoAuthAdapter(createConfig({ client, sessions }));
  const identifier = { kind: 'email' as const, value: 'player@example.org' };

  expect(await adapter.signUp({ identifier, password: 'S3cure-password!' })).toMatchObject({
    ok: true, data: { id: 'player-1', email: identifier.value },
  });
  expect(await adapter.signIn({ identifier, password: 'S3cure-password!' })).toMatchObject({
    ok: true, data: { user: { id: 'player-1' }, refreshToken: 'refresh-token' },
  });
  expect(await adapter.refreshSession()).toMatchObject({
    ok: true, data: { user: { id: 'player-1' }, accessToken: 'access-token' },
  });
  expect(await adapter.signOut()).toMatchObject({ ok: true });
  expect(await sessions.read()).toBeNull();
  expect(commands).toEqual([
    'AWSCognitoIdentityProviderService.SignUp',
    'AWSCognitoIdentityProviderService.InitiateAuth',
    'AWSCognitoIdentityProviderService.GetTokensFromRefreshToken',
    'AWSCognitoIdentityProviderService.RevokeToken',
  ]);
});

test('fails closed on a JWT verifier subject mismatch without saving a session', async () => {
  const { client } = createAwsSdkTestClient();
  const sessions = createSessionStore();
  const adapter = createCognitoAuthAdapter(
    createConfig({
      client,
      sessions,
      verifyJwt: () => Promise.resolve({ sub: '' }),
    }),
  );

  expect(
    await adapter.signIn({
      identifier: { kind: 'email', value: 'player@example.org' },
      password: 'S3cure-password!',
    }),
  ).toMatchObject({ ok: false, error: { code: 'authentication_failed' } });
  expect(await sessions.read()).toBeNull();
});
