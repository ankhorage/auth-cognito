import type { AuthSession } from '@ankhorage/contracts/auth';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

import type {
  CognitoAuthConfig,
  CognitoAuthorizationAttempt,
  CognitoAuthorizationAttemptStore,
  CognitoSessionStore,
} from './types/cognito.js';

/*** Provide an atomic durable-attempt-shaped fake for adapter behavior tests. */
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
export function createSessionStore(): CognitoSessionStore {
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
export function createConfig(overrides: Partial<CognitoAuthConfig> = {}): CognitoAuthConfig {
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
