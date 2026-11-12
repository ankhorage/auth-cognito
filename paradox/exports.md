# Public API

## CognitoAuthConfig

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:51:1`

Server/host-owned adapter dependencies; credentials remain within the SDK client.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| authorizationAttempts | property | `CognitoAuthorizationAttemptStore` | yes |  |
| authorizationAttemptTtlMs | property | `number \| undefined` | no |  |
| client | property | `CognitoIdentityProviderClient` | yes |  |
| createAttemptId | property | `(() => string) \| undefined` | no |  |
| http | property | `typeof fetch \| undefined` | no |  |
| now | property | `(() => number) \| undefined` | no |  |
| public | property | `CognitoPublicConfig` | yes |  |
| sessions | property | `CognitoSessionStore` | yes |  |
| verifyJwt | property | `CognitoJwtVerifier \| undefined` | no |  |

## CognitoAuthorizationAttempt

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:23:1`

Persist an OAuth PKCE authorization attempt with atomic one-time consumption.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| attemptId | property | `string` | yes |  |
| codeVerifier | property | `string` | yes |  |
| expiresAt | property | `number` | yes |  |
| nonce | property | `string` | yes |  |
| provider | property | `string` | yes |  |
| redirectUri | property | `string` | yes |  |
| state | property | `string` | yes |  |

## CognitoAuthorizationAttemptStore

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:33:1`

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| consume | method | `(attemptId: string, now: number) => Promise<CognitoAuthorizationAttempt \| null>` | yes |  |
| create | method | `(attempt: CognitoAuthorizationAttempt) => Promise<void>` | yes |  |

## CognitoJwtVerifier

Kind: `unknown`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:45:1`

Verify JWTs against this User Pool, app client, expiry, signature, and token use.

## CognitoPasswordResetCompletionInput

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:70:1`

Complete a previously requested password reset with the received confirmation code.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| code | property | `string` | yes |  |
| identifier | property | `AuthIdentifier` | yes |  |
| newPassword | property | `string` | yes |  |

## CognitoPublicConfig

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:5:1`

Public User Pool configuration; no AWS credentials or client secrets.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| clientId | property | `string` | yes |  |
| hostedDomain | property | `string` | yes |  |
| oauthProviders | property | `Readonly<Record<string, string>> \| undefined` | no |  |
| redirectUris | property | `readonly string[]` | yes |  |
| region | property | `string` | yes |  |
| scopes | property | `readonly string[] \| undefined` | no |  |
| userPoolId | property | `string` | yes |  |

## CognitoSessionStore

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:16:1`

Persist browser or native session tokens in a host-owned secure store.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| clear | method | `() => Promise<void>` | yes |  |
| read | method | `() => Promise<AuthSession \| null>` | yes |  |
| write | method | `(session: AuthSession) => Promise<void>` | yes |  |

## CognitoSignUpConfirmationInput

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:64:1`

Confirm registration without claiming Cognito has issued a signed session.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| code | property | `string` | yes |  |
| identifier | property | `AuthIdentifier` | yes |  |

## CognitoVerifiedClaims

Kind: `type`
Module: `src/types/cognito.ts`
Source: `src/types/cognito.ts:39:1`

Verified claims contain the stable Cognito sub identifier.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| nonce | property | `string \| undefined` | no |  |
| sub | property | `string` | yes |  |

## confirmCognitoPasswordResetAsync

Kind: `function`
Module: `src/features/auth/adapters/cognito/confirmCognitoPasswordResetAsync.ts`
Source: `src/features/auth/adapters/cognito/confirmCognitoPasswordResetAsync.ts:11:1`

Complete Cognito's password reset with a confirmed code and user-supplied new password.

### Signatures

- `(config: CognitoAuthConfig, input: CognitoPasswordResetCompletionInput) => Promise<AuthResult>`
  - config: `CognitoAuthConfig`
  - input: `CognitoPasswordResetCompletionInput`
  - returns: `Promise<AuthResult>`

## confirmCognitoSignUpAsync

Kind: `function`
Module: `src/features/auth/adapters/cognito/confirmCognitoSignUpAsync.ts`
Source: `src/features/auth/adapters/cognito/confirmCognitoSignUpAsync.ts:11:1`

Confirm registration without issuing or pretending to possess a Cognito session.

### Signatures

- `(config: CognitoAuthConfig, input: CognitoSignUpConfirmationInput) => Promise<AuthResult>`
  - config: `CognitoAuthConfig`
  - input: `CognitoSignUpConfirmationInput`
  - returns: `Promise<AuthResult>`

## createCognitoAuthAdapter

Kind: `function`
Module: `src/features/auth/adapters/cognito/createCognitoAuthAdapter.ts`
Source: `src/features/auth/adapters/cognito/createCognitoAuthAdapter.ts:27:1`

Implement the portable AuthPort through a host-owned AWS Cognito User Pool client.

### Signatures

- `(config: CognitoAuthConfig) => AuthPort`
  - config: `CognitoAuthConfig`
  - returns: `AuthPort`
