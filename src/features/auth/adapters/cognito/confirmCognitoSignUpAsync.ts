import type { AuthResult } from '@ankhorage/contracts/auth';
import { ConfirmSignUpCommand } from '@aws-sdk/client-cognito-identity-provider';

import type { CognitoAuthConfig, CognitoSignUpConfirmationInput } from '../../../../types/cognito.js';
import { cognitoAuthFailure } from './cognitoAuthFailure.js';

/*** Confirm registration without issuing or pretending to possess a Cognito session. */
export async function confirmCognitoSignUpAsync(
  config: CognitoAuthConfig,
  input: CognitoSignUpConfirmationInput,
): Promise<AuthResult> {
  if (!input.identifier.value.trim() || !input.code.trim()) {
    return cognitoAuthFailure('confirmation_input_invalid');
  }
  try {
    await config.client.send(
      new ConfirmSignUpCommand({
        ClientId: config.public.clientId,
        Username: input.identifier.value,
        ConfirmationCode: input.code,
      }),
    );
    return { ok: true };
  } catch {
    return cognitoAuthFailure('confirmation_failed');
  }
}
