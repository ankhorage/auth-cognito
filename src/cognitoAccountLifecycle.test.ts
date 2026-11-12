import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { expect, test } from 'bun:test';

import { createConfig, createSessionStore } from './cognitoTestSupport.test.js';
import {
  confirmCognitoPasswordResetAsync,
  confirmCognitoSignUpAsync,
  createCognitoAuthAdapter,
} from './index.js';

/*** Read only the typed AWS JSON command target from an untrusted SDK request. */
function readCognitoCommandName(request: unknown): string {
  if (typeof request !== 'object' || request === null || !('headers' in request)) {
    return '';
  }
  const { headers } = request;
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
        const result = target.endsWith('.SignUp')
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
    ok: true,
    data: { id: 'player-1', email: identifier.value },
  });
  expect(await adapter.signIn({ identifier, password: 'S3cure-password!' })).toMatchObject({
    ok: true,
    data: { user: { id: 'player-1' }, refreshToken: 'refresh-token' },
  });
  expect(await adapter.refreshSession()).toMatchObject({
    ok: true,
    data: { user: { id: 'player-1' }, accessToken: 'access-token' },
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

test('Cognito registration confirmation reports success without inventing an AuthSession', async () => {
  const { client, commands } = createAwsSdkTestClient();
  const config = createConfig({ client });
  const identifier = { kind: 'email' as const, value: 'player@example.org' };
  const adapter = createCognitoAuthAdapter(config);

  expect(await adapter.verifyOtp({ identifier, token: '123456' })).toMatchObject({
    ok: false,
    error: { code: 'otp_session_unavailable' },
  });
  expect(commands).toEqual([]);

  expect(await confirmCognitoSignUpAsync(config, { identifier, code: '123456' })).toEqual({
    ok: true,
  });
  expect(commands).toEqual(['AWSCognitoIdentityProviderService.ConfirmSignUp']);
  expect(await config.sessions.read()).toBeNull();
});

test('Cognito forgot-password initiation and confirmation are separate truthful operations', async () => {
  const { client, commands } = createAwsSdkTestClient();
  const config = createConfig({ client });
  const identifier = { kind: 'email' as const, value: 'player@example.org' };
  const adapter = createCognitoAuthAdapter(config);

  expect(await adapter.requestPasswordReset({ identifier })).toEqual({ ok: true });
  expect(
    await confirmCognitoPasswordResetAsync(config, {
      identifier,
      code: '123456',
      newPassword: 'A-strong-new-password!',
    }),
  ).toEqual({ ok: true });
  expect(commands).toEqual([
    'AWSCognitoIdentityProviderService.ForgotPassword',
    'AWSCognitoIdentityProviderService.ConfirmForgotPassword',
  ]);
  expect(await config.sessions.read()).toBeNull();
});

test('Cognito confirmation validates required inputs before contacting AWS', async () => {
  const { client, commands } = createAwsSdkTestClient();
  const config = createConfig({ client });
  const identifier = { kind: 'email' as const, value: 'player@example.org' };

  expect(await confirmCognitoSignUpAsync(config, { identifier, code: ' ' })).toMatchObject({
    ok: false,
    error: { code: 'confirmation_input_invalid' },
  });
  expect(
    await confirmCognitoPasswordResetAsync(config, {
      identifier,
      code: '123456',
      newPassword: '',
    }),
  ).toMatchObject({ ok: false, error: { code: 'password_reset_input_invalid' } });
  expect(commands).toEqual([]);
});
