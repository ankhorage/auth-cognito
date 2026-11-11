import type { AuthPort } from '@ankhorage/auth';
import type { AuthResult, AuthSession, AuthUser } from '@ankhorage/contracts/auth';
import {
  ConfirmSignUpCommand,
  ForgotPasswordCommand,
  GetTokensFromRefreshTokenCommand,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  RevokeTokenCommand,
  SignUpCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import type { AuthenticationResultType } from '@aws-sdk/client-cognito-identity-provider';

import type { CognitoAuthConfig } from '../../../../types/cognito.js';
import { createCognitoJwtVerifier } from './createCognitoJwtVerifier.js';
import { createCognitoOAuthHandlers } from './createCognitoOAuthHandlers.js';

/*** Implement the portable AuthPort through a host-owned AWS Cognito User Pool client. */
export function createCognitoAuthAdapter(config: CognitoAuthConfig): AuthPort {
  if (!config.public.clientId || !config.public.userPoolId || !config.public.region) {
    throw new Error('Cognito User Pool, region, and app client must be configured.');
  }
  const verifyJwt =
    config.verifyJwt ?? createCognitoJwtVerifier(config.public.userPoolId, config.public.clientId);
  const oauth = createCognitoOAuthHandlers(config, verifyJwt);
  return {
    signIn: async (input) => {
      if (!input.password) return failure('password_required');
      try {
        const result = await config.client.send(
          new InitiateAuthCommand({
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: config.public.clientId,
            AuthParameters: { USERNAME: input.identifier.value, PASSWORD: input.password },
          }),
        );
        if (!result.AuthenticationResult) return failure('challenge_required');
        const session = await resolveVerifiedSession(
          result.AuthenticationResult,
          verifyJwt,
          now(config),
        );
        await config.sessions.write(session);
        return { ok: true, data: session };
      } catch {
        return failure('authentication_failed');
      }
    },
    signUp: async (input) => {
      if (!input.password) return failure<AuthUser>('password_required');
      try {
        const result = await config.client.send(
          new SignUpCommand({
            ClientId: config.public.clientId,
            Username: input.identifier.value,
            Password: input.password,
            UserAttributes:
              input.identifier.kind === 'username'
                ? []
                : [{
                    Name: input.identifier.kind === 'phone' ? 'phone_number' : 'email',
                    Value: input.identifier.value,
                  }],
          }),
        );
        if (!result.UserSub) return failure<AuthUser>('provider_error');
        return {
          ok: true,
          data: {
            id: result.UserSub,
            ...(input.identifier.kind === 'email' ? { email: input.identifier.value } : {}),
            ...(input.identifier.kind === 'phone' ? { phone: input.identifier.value } : {}),
            ...(input.identifier.kind === 'username' ? { username: input.identifier.value } : {}),
          },
        };
      } catch {
        return failure<AuthUser>('registration_failed');
      }
    },
    signOut: async (input) => {
      try {
        const session = await config.sessions.read();
        if (session?.accessToken) {
          if (input?.allDevices) {
            await config.client.send(new GlobalSignOutCommand({ AccessToken: session.accessToken }));
          } else if (session.refreshToken) {
            await config.client.send(
              new RevokeTokenCommand({
                ClientId: config.public.clientId,
                Token: session.refreshToken,
              }),
            );
          }
        }
        await config.sessions.clear();
        return { ok: true };
      } catch {
        return failure('sign_out_failed');
      }
    },
    getSession: async () => {
      try {
        const session = await config.sessions.read();
        if (session === null) return { ok: true, data: null };
        const claims = await verifyJwt(session.accessToken, 'access');
        return claims.sub === session.user.id
          ? { ok: true, data: session }
          : failure<AuthSession | null>('invalid_session');
      } catch {
        return failure<AuthSession | null>('invalid_session');
      }
    },
    refreshSession: async () => {
      try {
        const previous = await config.sessions.read();
        if (!previous?.refreshToken) return failure<AuthSession | null>('refresh_unavailable');
        const result = await config.client.send(
          new GetTokensFromRefreshTokenCommand({
            ClientId: config.public.clientId,
            RefreshToken: previous.refreshToken,
          }),
        );
        if (!result.AuthenticationResult) return failure<AuthSession | null>('refresh_failed');
        const session = await resolveVerifiedSession(
          result.AuthenticationResult,
          verifyJwt,
          now(config),
          previous.refreshToken,
        );
        if (session.user.id !== previous.user.id) {
          return failure<AuthSession | null>('invalid_session');
        }
        await config.sessions.write(session);
        return { ok: true, data: session };
      } catch {
        return failure<AuthSession | null>('refresh_failed');
      }
    },
    requestPasswordReset: async (input) => {
      try {
        await config.client.send(
          new ForgotPasswordCommand({
            ClientId: config.public.clientId,
            Username: input.identifier.value,
          }),
        );
        return { ok: true };
      } catch {
        return failure('password_reset_failed');
      }
    },
    verifyOtp: async (input) => {
      try {
        await config.client.send(
          new ConfirmSignUpCommand({
            ClientId: config.public.clientId,
            Username: input.identifier.value,
            ConfirmationCode: input.token,
          }),
        );
        // An OTP confirmation does not issue tokens. Never fabricate an authenticated session.
        return failure<AuthSession>('sign_in_required_after_confirmation');
      } catch {
        return failure<AuthSession>('otp_verification_failed');
      }
    },
    startAuthorization: oauth.start,
    completeAuthorization: oauth.complete,
  };
}

/*** Validate the Cognito access JWT and derive the stable subject, never an email as identity. */
async function resolveVerifiedSession(
  tokens: AuthenticationResultType,
  verifyJwt: NonNullable<CognitoAuthConfig['verifyJwt']>,
  issuedAt: number,
  previousRefreshToken?: string,
): Promise<AuthSession> {
  if (!tokens.AccessToken || !tokens.ExpiresIn || tokens.ExpiresIn <= 0) {
    throw new Error('Cognito did not provide an access token with an expiration.');
  }
  const claims = await verifyJwt(tokens.AccessToken, 'access');
  if (!claims.sub) throw new Error('Cognito subject is missing.');
  return {
    accessToken: tokens.AccessToken,
    ...(tokens.RefreshToken || previousRefreshToken
      ? { refreshToken: tokens.RefreshToken ?? previousRefreshToken }
      : {}),
    expiresAt: issuedAt + tokens.ExpiresIn * 1000,
    tokenType: tokens.TokenType ?? 'Bearer',
    user: { id: claims.sub },
  };
}

/*** Convert provider exceptions into consistent secret-free auth errors. */
function failure<T = void>(code: string): AuthResult<T> {
  return { ok: false, error: { code, message: 'Cognito authentication operation failed.' } };
}

/*** Centralize time in milliseconds for session and OAuth expiration. */
function now(config: CognitoAuthConfig): number {
  return (config.now ?? Date.now)();
}
