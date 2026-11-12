import type { AuthResult } from '@ankhorage/contracts/auth';
import { ConfirmForgotPasswordCommand } from '@aws-sdk/client-cognito-identity-provider';

import type {
  CognitoAuthConfig,
  CognitoPasswordResetCompletionInput,
} from '../../../../types/cognito.js';
import { cognitoAuthFailure } from './cognitoAuthFailure.js';

/*** Complete Cognito's password reset with a confirmed code and user-supplied new password. */
export async function confirmCognitoPasswordResetAsync(
  config: CognitoAuthConfig,
  input: CognitoPasswordResetCompletionInput,
): Promise<AuthResult> {
  if (!input.identifier.value.trim() || !input.code.trim() || !input.newPassword) {
    return cognitoAuthFailure('password_reset_input_invalid');
  }
  try {
    await config.client.send(
      new ConfirmForgotPasswordCommand({
        ClientId: config.public.clientId,
        Username: input.identifier.value,
        ConfirmationCode: input.code,
        Password: input.newPassword,
      }),
    );
    return { ok: true };
  } catch {
    return cognitoAuthFailure('password_reset_confirmation_failed');
  }
}
