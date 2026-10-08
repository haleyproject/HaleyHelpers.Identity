# Haley Identity API reference

Standalone base path: `/api/identity`. Kida base path: `/api/kida/identity/foundation`. Both use the same JSON request/result contracts and the same generated route mappings. Existing Kida routes remain available.

Every standalone application API call includes `X-Haley-Application-Id`, `X-Haley-Session-Key-Id` and `X-Haley-Session-Key`. This applies to account management, MFA, verification, federation initiation/discovery and sessions. The configured private network boundary is still required. Missing application IDs return 400; missing, invalid or revoked credentials return 401 with `invalid_session_binding`. Kida calls instead include its bearer machine token and `X-Kida-Identity-Resource`; the application GUID must match the authenticated client. The SDK supplies these headers from configuration. Browser federation callbacks continue to authenticate provider proof instead of application headers.

The standalone admin console uses its existing management login and CSRF protection for application registration. Application credentials cannot access these management routes:

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/admin/api/applications` | List application IDs, display names, numeric statuses and key IDs. Never returns secrets. |
| POST | `/admin/api/applications` | Register `{ "displayName": "LearnDesk", "applicationId": "optional-guid" }`; omit the ID to generate one. Returns the new credential once. |
| POST | `/admin/api/applications/{id}/keys` | Issue a new key. Existing keys remain valid during the caller's transition. Returns the new credential once. |
| POST | `/admin/api/applications/{id}/reactivate` | Reactivate a revoked application with the same ID and a fresh credential. Previously revoked keys remain invalid. Returns 409 if already active. |
| DELETE | `/admin/api/applications/{id}/keys/{keyId}` | Revoke a specific key. Removing the final key requires revoking the application instead. |
| DELETE | `/admin/api/applications/{id}` | Revoke all application keys and retain a revoked registry entry. Does not delete user data or session records. |

Registration, rotation and reactivation return `applicationId`, `sessionKeyId` and `sessionBindingSecret` with `Cache-Control: no-store`. Registry statuses use numeric `IdentityRecordStatus` values on the wire even when a host uses string serialization for other enums: Active = 2 and Revoked = 64. Applications cannot manage their own credentials through the application API; these are management operations. Registry changes are configuration-backed and do not change the SQL schema.

| SDK operation | HTTP method | Relative path |
| --- | --- | --- |
| `GetAccountAsync` | GET | `accounts/{userId}` |
| `FindAccountAsync` | POST | `accounts/resolve` |
| `EnsureAccountAsync` | POST | `accounts` |
| `ListAccountsAsync` | POST | `accounts/search` |
| `GetProfileAsync` | GET | `accounts/{userId}/profile` |
| `UpdateProfileAsync` | PUT | `accounts/{userId}/profile` |
| `SetAccountStatusAsync` | PATCH | `accounts/{userId}/status` |
| `SetPasswordAsync` | PUT | `accounts/{userId}/password` |
| `ChangePasswordAsync` | POST | `password/changes` |
| `AuthenticatePasswordAsync` | POST | `sessions/password` |
| `AuthenticateTotpAsync` | POST | `sessions/totp` |
| `CreateApplicationSessionAsync` | POST | `sessions/application` |
| `ValidateSessionAsync` | POST | `sessions/validation` |
| `RevokeSessionAsync` | DELETE | `sessions` |
| `ListLoginAttemptsAsync` | POST | `login-attempts/search` |
| `ReleaseAccountLockAsync` | POST | `accounts/{userId}/lock/release` |
| `ListMfaMethodsAsync` | GET | `accounts/{userId}/mfa-methods` |
| `BeginTotpEnrollmentAsync` | POST | `mfa/enrollments` |
| `InspectTotpEnrollmentAsync` | POST | `mfa/enrollments/inspection` |
| `ConfirmTotpEnrollmentAsync` | POST | `mfa/enrollments/confirmation` |
| `RetireMfaMethodAsync` | DELETE | `accounts/{userId}/mfa-methods/{methodId}` |
| `ReplaceRecoveryCodesAsync` | POST | `mfa/recovery-codes` |
| `VerifyMfaAsync` | POST | `mfa/verification` |
| `BeginPasswordResetAsync` | POST | `password/resets` |
| `VerifyPasswordResetCodeAsync` | POST | `password/resets/verification` |
| `CompletePasswordResetAsync` | POST | `password/resets/completion` |
| `GetEmailVerificationAsync` | POST | `verification/email/status` |
| `BeginVerificationAsync` | POST | `verification/{purpose}/challenges` |
| `CompleteVerificationAsync` | POST | `verification/{purpose}/completion` |

Successful operations return their result payload or 204. Failures use ProblemDetails with useful detail and a stable code; the SDK converts this to Haley Feedback. The server never serializes password hashes, protection-key material or internal numeric row identifiers. MFA enrollment data, reset delivery material and newly issued opaque tokens are intentionally sensitive one-time results for the trusted application.

## Kida scope mapping

| Operation group | Required scope |
| --- | --- |
| Read/resolve an account or profile | `identity.users.resolve` |
| Ensure a minimal account | `identity.accounts.ensure` |
| Password or primary authenticator authentication | `identity.authenticate` |
| Application-attested session | `identity.sessions.issue`; also `identity.accounts.ensure` when CreateIfMissing is true |
| Validate / revoke opaque session | `identity.sessions.validate` / `identity.sessions.revoke` |
| List/enroll/confirm/retire MFA or replace recovery codes | `identity.mfa.manage` |
| Verify an MFA factor | `identity.mfa.verify` |
| Request/verify/complete password recovery | `identity.password.reset.request` |
| List accounts, update profiles/status/passwords, inspect login attempts, release locks | `identity.users.manage` |

These are machine scopes on the Kida service API. Every request also verifies current client authority for the requested application resource. Registering the 1.4.0 Identity scope catalog does not add grants to existing clients. An application's assertion is accepted only with the dedicated session-issuance privilege; a machine token without that privilege cannot skip password login.

## Primary authenticator login

Primary authenticator login uses `TotpAuthenticationRequest(Email, Code, MethodId?, Kind)` and requires `TotpLogin:Enabled`. Optional `TotpLogin:ApplicationIds` limits eligible applications. Accounts require verified email and an active enrolled TOTP method. `Kind` defaults to TOTP; RecoveryCode accepts a one-use recovery proof. The resulting session records one factor only. Kida enforces explicit MFA requirements before consuming the proof. See [authentication workflows](AUTHENTICATION.md).

## Purpose-bound verification

The SDK selects the route from `VerificationPurpose`. JSON sends the numeric enum value, and the body purpose must match the route. Combined or undefined values are rejected. See [workflow examples](VERIFICATION.md).

| Purpose | Numeric value | Route segment | Kida machine scope | Completion behavior |
| --- | --- | --- | --- | --- |
| EmailVerification | 1 | `email` | `identity.users.manage` | Verify the exact existing email contact and enable recovery; preserve account status |
| Onboarding | 2 | `onboarding` | `identity.users.invite` | Verify the contact, optionally set an initial password, activate a pending account |
| PasswordReset | 4 | `password-reset` | `identity.password.reset.request` | Require `NewPassword`, replace the credential, enforce history, revoke sessions |
| PasswordlessLogin | 8 | `login` | `identity.authenticate` | Require verified recovery contact and active account; enforce MFA and issue opaque session |

`GetEmailVerificationAsync` requires `identity.users.resolve` in Kida. Existing live client/resource checks apply to every route. No new OAuth scope grants are installed automatically.

Begin accepts `Email`, `Purpose`, `ProofKind` (1 OpaqueToken, 2 NumericCode), optional `ValiditySeconds`, and optional `Context` (at most 1000 characters). The account and contact must already exist. `InitialStatus` on `EnsureAccountRequest` accepts only Pending (1) or Active (2); Active remains the default, and existing account status is preserved.

Begin returns `IdentityVerificationInitiation` with `Accepted=true`. Unknown, blocked, ineligible, and throttled requests have no `Delivery`. An eligible request returns a delivery containing `ChallengeId`, `Purpose`, `ProofKind`, `Destination`, `Verifier`, `ExpiresAt`, and `ResendAllowedAt`. This material is for the trusted backend. Public-facing application handlers should return a generic acknowledgement and deliver the verifier separately. The library does not send mail or build URLs.

Complete accepts `ChallengeId`, the original `Purpose`/`ProofKind`/`Context`, and `Verifier`. PasswordReset requires `NewPassword`. Onboarding accepts `NewPassword` and requires it when the account is flagged for an initial password change. Other purposes reject it. PasswordlessLogin also accepts `MfaKind`, `MfaMethodId`, and `MfaCode`.

The result contains `UserId`, `Purpose`, `EmailVerified`, `AccountStatus`, and an optional `Session` present only for email login. Email/account verification and password reset do not sign the user in. Correcting an invalid/reused new password can reuse the still-pending verifier; a successful completion cannot be repeated.

Expiry, attempt exhaustion, replay, application/context mismatch, changed destination and changed credentials are enforced. Resending replaces the pending challenge after the existing verification-policy cooldown. Email login's proof consumption and opaque session insertion are atomic, as are verification/password/account changes. State changes or credential replacement during completion cause rejection. An application link is only a carrier for the verifier and challenge metadata; completion is a POST with the sensitive payload in its body. Merely loading a link must not consume it.

## Corporate authentication and management

The reusable `IIdentityFederation` contract and full request/response flow are described in [FEDERATION.md](FEDERATION.md). The standalone host also serves `/admin/` and its password/cookie-protected `/admin/api` endpoints. These are host management routes; they are not part of the portable client API.

Corporate begin accepts an empty `ProviderCode` and optional `EmailOrDomain`. Discovery accepts `EmailOrDomain`, `ApplicationId`, and `Context`, and returns only permitted candidates with `IsDefault`. Applications should handle HTTP 409 / `identity.federation_provider_selection_required` by displaying discovery results. Signed callbacks use contract version 1; existing assertions that omit the version remain valid. See [provider selection and contract details](FEDERATION.md).
