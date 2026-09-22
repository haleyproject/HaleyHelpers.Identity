# Haley Identity API reference

Standalone base path: `/api/identity`. Kida base path: `/api/kida/identity/foundation`. Both use the same JSON request/result contracts and the same generated route mappings. Existing Kida routes remain available.

Every standalone call includes `X-Haley-Application-Id`. Session operations additionally require `X-Haley-Session-Key-Id` and `X-Haley-Session-Key`. Other standalone operations trust the private network boundary. Kida calls instead include its bearer machine token and `X-Kida-Identity-Resource`; the application GUID must match the authenticated client. The SDK supplies these headers from configuration.

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

Successful operations return their result payload or 204. Failures use ProblemDetails with useful detail and a stable code; the SDK converts this to Haley Feedback. The server never serializes password hashes, protection-key material or internal numeric row identifiers. MFA enrollment data, reset delivery material and newly issued opaque tokens are intentionally sensitive one-time results for the trusted application.

## Kida scope mapping

| Operation group | Required scope |
| --- | --- |
| Read/resolve an account or profile | `identity.users.resolve` |
| Ensure a minimal account | `identity.accounts.ensure` |
| Password authentication | `identity.authenticate` |
| Application-attested session | `identity.sessions.issue`; also `identity.accounts.ensure` when CreateIfMissing is true |
| Validate / revoke opaque session | `identity.sessions.validate` / `identity.sessions.revoke` |
| List/enroll/confirm/retire MFA or replace recovery codes | `identity.mfa.manage` |
| Verify an MFA factor | `identity.mfa.verify` |
| Request/verify/complete password recovery | `identity.password.reset.request` |
| List accounts, update profiles/status/passwords, inspect login attempts, release locks | `identity.users.manage` |

These are machine scopes on the Kida service API. Every request also verifies current client authority for the requested application resource. Registering the 1.4.0 Identity scope catalog does not add grants to existing clients. An application's assertion is accepted only with the dedicated session-issuance privilege; a machine token without that privilege cannot skip password login.
