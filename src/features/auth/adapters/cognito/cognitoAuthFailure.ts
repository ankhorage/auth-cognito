import type { AuthResult } from '@ankhorage/contracts/auth';

/*** Normalize Cognito failures without leaking tokens, provider messages or credentials. */
export function cognitoAuthFailure<T = void>(code: string): AuthResult<T> {
  return { ok: false, error: { code, message: 'Cognito authentication operation failed.' } };
}
