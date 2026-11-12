import { CognitoJwtVerifier } from 'aws-jwt-verify';

import type { CognitoJwtVerifier as VerifyCognitoJwt } from '../../../../types/cognito.js';

/*** Verify access and ID JWTs with the configured User Pool and Cognito app client. */
export function createCognitoJwtVerifier(userPoolId: string, clientId: string): VerifyCognitoJwt {
  const accessVerifier = CognitoJwtVerifier.create({
    userPoolId,
    clientId,
    tokenUse: 'access',
  });
  const idVerifier = CognitoJwtVerifier.create({
    userPoolId,
    clientId,
    tokenUse: 'id',
  });
  return async (token, tokenUse) => {
    const payload =
      tokenUse === 'access' ? await accessVerifier.verify(token) : await idVerifier.verify(token);
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new Error('Cognito JWT subject is missing.');
    }
    return {
      sub: payload.sub,
      ...('nonce' in payload && typeof payload.nonce === 'string' ? { nonce: payload.nonce } : {}),
    };
  };
}
