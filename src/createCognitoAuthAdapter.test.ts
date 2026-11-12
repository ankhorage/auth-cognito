import { expect, test } from 'bun:test';

import { createConfig, createSessionStore } from './cognitoTestSupport.test.js';
import { createCognitoAuthAdapter } from './index.js';
import type { CognitoAuthConfig } from './types/cognito.js';

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
