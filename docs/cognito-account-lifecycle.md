# Cognito User Pool adapter

`@ankhorage/auth-cognito` implements the published `AuthPort`. It does not own any database
records, DynamoDB tables, or GrossMeister application-specific session logic.

## Production ownership

Supply a correctly configured `CognitoIdentityProviderClient` through the host. Keep AWS
credentials in the host's IAM/secret boundary. Only the User Pool, Region, public app-client ID,
OAuth domain and redirect allowlist belong in `CognitoPublicConfig`.

Create the adapter per user request/session, not as a process-global mutable user context.
The host injects its own secure `CognitoSessionStore` and **atomic, durable, TTL-aware**
`CognitoAuthorizationAttemptStore`. Neither store should hold shared mutable login state
without actor/request scoping.

Cognito's stable JWT `sub` is the identity that downstream business adapters may map to
game ownership. Never use e-mail or mutable usernames as primary identifiers.

## Supported authentication

- User Pool username/password sign-in with `USER_PASSWORD_AUTH` where enabled by the app client.
- Registration returns the new unconfirmed or confirmed user, not fabricated session tokens.
- Explicit `confirmCognitoSignUpAsync(config, { identifier, code })` confirms a registration and
  returns `{ ok: true }` on success. It never fabricates a session. A real sign-in follows.
- The neutral `AuthPort.verifyOtp` cannot return a session from Cognito registration confirmation.
  It therefore returns `otp_session_unavailable` **without modifying the account**; the host uses
  the explicit confirmation operation instead.
- Password-reset initiation is provided through `requestPasswordReset` and completion through
  `confirmCognitoPasswordResetAsync(config, { identifier, code, newPassword })`.
- Session validation using `aws-jwt-verify` with exact User Pool, client ID and token-use claims.
- Refresh through `GetTokensFromRefreshToken`, including refresh-token rotation.
- Sign-out revokes refresh tokens for a single session or uses Cognito GlobalSignOut when requested.
- Browser/native OAuth authorization-code + S256 PKCE. The callback is single-use, checks state,
  redirect URI and ID-token nonce, and validates Cognito access and ID JWTs.

Do not store authorization codes, PKCE verifiers, refresh tokens, or access tokens in client URLs,
analytics events, GitHub logs, or plaintext unscoped application persistence.

This module is a provider adapter; browser cookies, native secure storage, callback orchestration,
IAM, resource ownership, and protected DynamoDB queries remain the responsibility of their
respective hosts/adapters.
