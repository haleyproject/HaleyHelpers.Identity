# Account authentication

Accounts can use passwords, email OTP/links, corporate authentication or an enrolled authenticator as their primary login method. No password is needed to create an account: create it pending, complete email onboarding or trusted account verification, then enroll and confirm TOTP. Applications deliver email proofs and present their login screens. The standalone API requires a registered application's binding credentials; Kida requires its authenticated OAuth client and scopes.

## Enable authenticator login

Set `Haley:Identity:Server:TotpLogin:Enabled=true` for standalone Haley, or `Kida:Identity:TotpLogin:Enabled=true` for Kida. Both default to false. `TotpLogin:ApplicationIds` optionally restricts the feature to listed application/client GUIDs. Empty permits all authorized applications when enabled. Restart the host after changing these settings. Environment variables and User Secrets retain normal precedence. The existing SecretProtection key ring encrypts authenticator seeds.

Use `IIdentity.AuthenticateTotpAsync(new TotpAuthenticationRequest(email, code))` through `AddHaleyIdentity`. Routes are `POST /api/identity/sessions/totp` and Kida's `POST /api/kida/identity/foundation/sessions/totp`. The Kida facade requires `identity.authenticate` and its configured resource header. These return the same opaque-session contract as password login.

For Kida access/refresh tokens, use `IKidaClient.AuthenticateTotpAsync(new AuthenticateTotpRequest(email, code, clientId, resource))`. The configured client binds its client ID and user audience, and obtains the required machine token. Its native route is `POST /api/kida/identity/sessions/totp`. All proofs go in the request body. AuthEdge exposes `POST /api/auth/sessions/totp` only with `MapRawSessionEndpoints=true`. Browser products using cookies should call the client from their own BFF and retain tokens in the backend.

An optional MethodId selects one authenticator; otherwise active TOTP methods belonging to the account are checked. Login requires an active account, verified email and active enrolled authenticator. Unknown/inactive accounts, unverified email, missing factors, incorrect codes and replays share a credential rejection. Failed guesses contribute to existing account lockout, and expired automatic locks use the existing release flow. Required password changes cannot be bypassed. The session transaction rechecks active account state.

## Strength and recovery

Primary authenticator login is single-factor. Session authentication methods contain only `totp`; the email identifies the account. Kida's explicit client, domain and user requirements for MFA block this route. Optional policy permits primary TOTP while the existing password flow still requires the enrolled second factor. Explicit user exceptions keep their existing precedence.

To recover, send an issued recovery code with `Kind=MfaKind.RecoveryCode` through the same route. It is consumed once, requires an active enrolled authenticator, and records only `recovery` in session authentication methods. Use the existing authorized enrollment/replacement flow to replace a lost device after recovery. Losing every authenticator and recovery code requires a trusted recovery process. An email address alone never authorizes enrollment or replacement.

Enrollment confirmation consumes its code; use a fresh code for subsequent login. Existing verification enforces one use across applications/login methods, a 30-second step, bounded clock tolerance and account lockout. Keep recovery codes private, retain protection keys with backups and use TLS. TOTP remains susceptible to phishing. Passkeys are a separate future feature.

Existing contact, MFA, recovery, account-lock, session and history storage is reused. No schema migration is required.
