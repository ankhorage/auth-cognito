import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { expect, test } from 'bun:test';

const userPoolId = 'eu-central-1_fixture';
const clientId = 'client_fixture';
const issuer = `https://cognito-idp.eu-central-1.amazonaws.com/${userPoolId}`;
const keyId = 'trusted-test-key';

/*** Encode a compact JWT segment using the same URL-safe alphabet as Cognito. */
function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

/*** Sign a real RSA JWT with locally generated test keys rather than a fake verifier. */
async function signJwt(payload: Readonly<Record<string, unknown>>, privateKey: CryptoKey): Promise<string> {
  const encoder = new TextEncoder();
  const header = base64Url(encoder.encode(JSON.stringify({ alg: 'RS256', kid: keyId, typ: 'JWT' })));
  const body = base64Url(encoder.encode(JSON.stringify(payload)));
  const unsigned = `${header}.${body}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, encoder.encode(unsigned)),
  );
  return `${unsigned}.${base64Url(signature)}`;
}

/*** Generate a local key pair whose public JWK is accepted by the real Cognito JWT verifier. */
async function createSigningKey() {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const exported = await crypto.subtle.exportKey('jwk', pair.publicKey);
  if (!exported.n || !exported.e) throw new Error('RSA test key lacks modulus or exponent.');
  return {
    privateKey: pair.privateKey,
    jwk: { kty: 'RSA' as const, kid: keyId, alg: 'RS256' as const, use: 'sig' as const, n: exported.n, e: exported.e },
  };
}

test('Cognito signed access JWT rejects bad issuer, client, use, expiry and signature', async () => {
  const trusted = await createSigningKey();
  const untrusted = await createSigningKey();
  const verifier = CognitoJwtVerifier.create({
    userPoolId,
    clientId,
    tokenUse: 'access',
  });
  verifier.cacheJwks({ keys: [trusted.jwk] });

  const now = Math.floor(Date.now() / 1_000);
  const claims = {
    sub: 'player-stable-sub',
    iss: issuer,
    token_use: 'access',
    client_id: clientId,
    auth_time: now - 30,
    iat: now - 30,
    exp: now + 300,
  };

  const valid = await signJwt(claims, trusted.privateKey);
  expect(verifier.verifySync(valid).sub).toBe('player-stable-sub');

  const invalidClaims = [
    { ...claims, iss: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_other' },
    { ...claims, client_id: 'another-client' },
    { ...claims, token_use: 'id' },
    { ...claims, exp: now - 300 },
  ];
  for (const payload of invalidClaims) {
    const token = await signJwt(payload, trusted.privateKey);
    expect(() => verifier.verifySync(token)).toThrow();
  }
  const forged = await signJwt(claims, untrusted.privateKey);
  expect(() => verifier.verifySync(forged)).toThrow();
});

test('Cognito ID JWT enforces signed client audience and correct token use', async () => {
  const trusted = await createSigningKey();
  const verifier = CognitoJwtVerifier.create({
    userPoolId,
    clientId,
    tokenUse: 'id',
  });
  verifier.cacheJwks({ keys: [trusted.jwk] });
  const now = Math.floor(Date.now() / 1_000);
  const claims = {
    sub: 'player-stable-sub',
    iss: issuer,
    token_use: 'id',
    aud: clientId,
    nonce: 'oidc-binding-value',
    iat: now - 30,
    exp: now + 300,
  };

  const valid = await signJwt(claims, trusted.privateKey);
  expect(verifier.verifySync(valid).sub).toBe('player-stable-sub');
  const wrongAudience = await signJwt({ ...claims, aud: 'untrusted-client' }, trusted.privateKey);
  expect(() => verifier.verifySync(wrongAudience)).toThrow();
  const wrongUse = await signJwt({ ...claims, token_use: 'access' }, trusted.privateKey);
  expect(() => verifier.verifySync(wrongUse)).toThrow();
});
