import type { AuthIdentifier, AuthSession } from '@ankhorage/contracts/auth';
import type { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

/*** Public User Pool configuration; no AWS credentials or client secrets. */
export interface CognitoPublicConfig {
  readonly region: string;
  readonly userPoolId: string;
  readonly clientId: string;
  readonly hostedDomain: string;
  readonly redirectUris: readonly string[];
  readonly oauthProviders?: Readonly<Record<string, string>>;
  readonly scopes?: readonly string[];
}

/*** Persist browser or native session tokens in a host-owned secure store. */
export interface CognitoSessionStore {
  read(): Promise<AuthSession | null>;
  write(session: AuthSession): Promise<void>;
  clear(): Promise<void>;
}

/*** Persist an OAuth PKCE authorization attempt with atomic one-time consumption. */
export interface CognitoAuthorizationAttempt {
  readonly attemptId: string;
  readonly redirectUri: string;
  readonly provider: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly expiresAt: number;
}

export interface CognitoAuthorizationAttemptStore {
  create(attempt: CognitoAuthorizationAttempt): Promise<void>;
  consume(attemptId: string, now: number): Promise<CognitoAuthorizationAttempt | null>;
}

/*** Verified claims contain the stable Cognito sub identifier. */
export interface CognitoVerifiedClaims {
  readonly sub: string;
  readonly nonce?: string;
}

/*** Verify JWTs against this User Pool, app client, expiry, signature, and token use. */
export type CognitoJwtVerifier = (
  token: string,
  tokenUse: 'access' | 'id',
) => Promise<CognitoVerifiedClaims>;

/*** Server/host-owned adapter dependencies; credentials remain within the SDK client. */
export interface CognitoAuthConfig {
  readonly public: CognitoPublicConfig;
  readonly client: CognitoIdentityProviderClient;
  readonly sessions: CognitoSessionStore;
  readonly authorizationAttempts: CognitoAuthorizationAttemptStore;
  readonly verifyJwt?: CognitoJwtVerifier;
  readonly http?: typeof fetch;
  readonly now?: () => number;
  readonly createAttemptId?: () => string;
  readonly authorizationAttemptTtlMs?: number;
}

/*** Confirm registration without claiming Cognito has issued a signed session. */
export interface CognitoSignUpConfirmationInput {
  readonly identifier: AuthIdentifier;
  readonly code: string;
}

/*** Complete a previously requested password reset with the received confirmation code. */
export interface CognitoPasswordResetCompletionInput {
  readonly identifier: AuthIdentifier;
  readonly code: string;
  readonly newPassword: string;
}
