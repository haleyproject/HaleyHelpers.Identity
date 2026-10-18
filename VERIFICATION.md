# Verification workflows

## Admin generation and recipient pages

In Haley or Kida Admin, open **Identity → Verification & onboarding**. Select the application (and Kida resource), the existing account email, purpose, OTP or opaque-token proof, and expiry. Generate the challenge, then copy its recipient link. For OTP, deliver the code separately. The identity host does not send email; your email engine can deliver the exact link displayed in the console. Generation remains behind the administration session and CSRF boundary.

The form loads active email contacts recorded on the selected account, including accounts whose login username is not an email address. Choose the intended mailbox from that list. A missing application/audience or contact is explained beside the disabled generation button. The email-contact lookup is management-only; public recipient pages do not expose account contact lists.

The shared recipient page is `/identity/verify/` in Haley Identity Host, Kida Service, and Kida Admin. Kida Admin obtains the same assets from its private Service connection, rather than exposing administration credentials or copying the verification engine. The recipient needs no administrator login. GET renders the page and assets; only explicit form submission attempts completion. Proofs remain bound to their original application, email, purpose and context, with expiry, attempt limits and one-use consumption.

Set `Haley:Identity:Server:Verification:PageUrl` or `Kida:Identity:Verification:PageUrl` to a public identity-hosted page when desired. `Verification:ApplicationPageUrls:<application-guid>` can select a public application-hosted page for that application's links. Blank values use the current identity-hosted page. The admin form can override the recipient-page URL for a particular delivery. Host configuration changes require a restart.

For private identity deployments, the recipient URL must belong to the public application. Its backend calls private Identity using the same completion contract and its configured credentials. The fragment contains the proof metadata; it is removed from browser history after the page opens and is never sent in a GET request. All proof submissions use POST bodies. Do not put an application binding secret or OAuth client secret in the link or browser.

Applications can reuse the page with `MapIdentityVerificationProxyEndpoints` from `Haley.Helpers.Identity.Server`, after registering their existing embedded/remote `IIdentity` client. This mapping only serves page assets and delegates completion; it does not register a database engine. Configure a rate-limit policy, the fixed application GUID and resource:

```csharp
// Register IIdentity with AddHaleyIdentity(...).UseRemote() or UseKida(...) first.
builder.Services.AddAdminLoginRateLimit("verification", 30);
// After building the application:
app.UseRateLimiter();
app.MapIdentityVerificationProxyEndpoints(applicationId, "haley.identity", "verification");
```

Use `haley.identity` for standalone Haley, or the configured product audience for Kida. Import `Haley.Extensions` and `Haley.Utils`. A link identifying another application or resource is rejected before the backend client is called. The page assets and completion endpoint use relative paths and work under a reverse-proxy prefix; use a page-directory URL with its trailing slash.

With a remote backend, the proxy uses the bound recipient-completion route without transmitting binding secrets or requesting machine-token scopes. Issuance and normal account APIs retain their existing authentication requirements. The identity server still checks active application/resource authority and the original one-time proof. `CompleteVerificationAsync` remains available as the authenticated application API.

Programmatic callers can use `IdentityVerificationLinks.Create(pageUrl, applicationId, resource, delivery, context, requiresPassword)` to produce the same link from an existing `BeginVerificationAsync` delivery. Opaque links carry the verifier in their fragment. OTP links carry the challenge metadata and ask the recipient for the separately delivered code. Preserve the original Context exactly at completion.

If an identity host is selectively published, expose only `/identity/verify/` and its assets/completion routes through the proxy. Keep `/admin/api`, management sessions and trusted application APIs inside their intended boundary. Applications that use passwordless-login links retain responsibility for establishing their own product cookies/sessions after proof completion.

Email verification preserves account status. Onboarding can activate a pending account, and password recovery updates its password. No additional tables or schema migrations are required.

## Administrative email ownership

The account Overview shows every recorded email and its Verified/Unverified state. In Verification, the standalone console offers **Break-glass verify** and **Mark unverified**, with a required reason and confirmation. These actions require the administrator session and antiforgery token, but no application selection or email proof. Break-glass verify also repairs a verified contact whose recovery flag is disabled. Mark unverified disables recovery and invalidates outstanding challenges and unconsumed grants for that mailbox. Both actions record an outbox attestation and preserve account lifecycle state.

An already verified email can receive another **Verify email** challenge to simulate the ceremony. Passwordless sign-in requires an Active account, a verified recovery-enabled email and no required password change; password recovery additionally requires an existing password. Verifying email alone does not activate a Pending account. Administrator challenge issuance explains these eligibility failures; normal application issuance retains its enumeration-safe acknowledgement.

The management operation is `PUT /admin/api/verification/accounts/{userId}/email-contacts/{contactId}/verification`, with `isVerified` and `reasonCode`. No database schema migration is required.

## Application API workflows

`AddHaleyIdentity` exposes the same `IIdentity` operations with `UseEmbedded`, `UseRemote`, or `UseKida`. Import `Haley.Models` for the request records and numeric enums. Password login, TOTP, recovery codes, email login, email verification, onboarding and password reset belong to the shared engine. Kida retains its authorization, MFA policy and OAuth token behavior.

## Create an unverified pending account

```csharp
var created = await identity.EnsureAccountAsync(new(
    "person@example.com", "Person", InitialStatus: IdentityStatus.Pending), cancellationToken);
if (!created.Status) { /* handle created.Key / created.Message */ }
```

The contact is unverified and cannot be used for email login or password recovery. A pending account cannot start a session, including through trusted application assertion. An existing account is returned without changing its lifecycle state. To inspect email status, call `GetEmailVerificationAsync(email)`.

## Issue a three-day onboarding link

```csharp
var started = await identity.BeginVerificationAsync(new(
    "person@example.com", VerificationPurpose.Onboarding,
    ProofKind: VerificationProofKind.OpaqueToken,
    ValiditySeconds: 3 * 24 * 60 * 60,
    Context: "invitation-123"), cancellationToken);

if (started.Status && started.Result.Delivery is { } delivery)
{
    // Deliver to delivery.Destination using your application's chosen channel.
    // Your link carries delivery.ChallengeId and delivery.Verifier.
    // Preserve Purpose, ProofKind and Context in the application flow.
}
```

The application owns email, SMS, manual delivery, URL construction and the setup screen. Delivery must reach the owner of the registered contact; handing the verifier to the unauthenticated requester does not prove ownership. Never return delivery material as a public acknowledgement, log it, or place it in analytics. A GET/link preview should show the setup screen; the subsequent explicit action sends completion to Identity.

```csharp
var completed = await identity.CompleteVerificationAsync(new(
    challengeId, VerificationPurpose.Onboarding, submittedVerifier,
    Context: "invitation-123", NewPassword: submittedNewPassword), cancellationToken);
```

Success verifies that exact contact, enables it for recovery, sets the password if supplied, and activates the pending account in one transaction. A password-free account can omit NewPassword unless an initial password change is required. It does not create a login session. Retired, suspended, locked or already active accounts cannot be reactivated by an onboarding verifier.

## Verify email without activating an account

Use `VerificationPurpose.EmailVerification`. Completion verifies the existing contact and enables recovery, while preserving account status. Supply no password. This can precede onboarding, or verify an active account's email. An arbitrary email that is not already associated with an account cannot be verified through this operation.

## Email OTP login

```csharp
var started = await identity.BeginVerificationAsync(new(
    email, VerificationPurpose.PasswordlessLogin,
    VerificationProofKind.NumericCode), cancellationToken);
// Deliver started.Result.Delivery.Verifier to Delivery.Destination.

var authenticated = await identity.CompleteVerificationAsync(new(
    challengeId, VerificationPurpose.PasswordlessLogin, submittedCode,
    VerificationProofKind.NumericCode,
    MfaKind: selectedMfaKind, MfaMethodId: selectedMfaMethodId, MfaCode: submittedMfaCode), cancellationToken);
```

An active account and verified, recovery-enabled contact are required. Successful completion returns `Result.Session`, with an opaque token and expiry. Enrolled MFA remains mandatory on standalone hosts; Kida applies its existing client/domain/user policy. Missing MFA returns `mfa_required`; the pending proof can be submitted again with the factor. Wrong factors apply login protection. The application owns its cookie/session integration. Use OpaqueToken instead of NumericCode to build an email login link.

Standalone remote login initiation and completion require the configured application session-binding key. UseKida supplies its machine token and requires `identity.authenticate`; opaque-session issuance remains application/resource bound. Kida's existing passwordless OAuth endpoint still returns its usual access/refresh tokens, using the same Haley proof engine.

## Reset a password with one verifier

Use `VerificationPurpose.PasswordReset`, choosing NumericCode or OpaqueToken. The account must be active with a verified recovery contact and an existing password. Then complete with the verifier and `NewPassword` together:

```csharp
var reset = await identity.CompleteVerificationAsync(new(
    challengeId, VerificationPurpose.PasswordReset, submittedVerifier,
    NewPassword: submittedNewPassword), cancellationToken);
```

Use the original ProofKind and Context if they differ from the defaults. Successful replacement enforces password history and revokes existing sessions. Kida also revokes refresh families through its persistence extension. No login session is created. A changed credential invalidates older reset/login proofs. If the password is rejected as invalid or reused, the transaction does not consume the proof.

An authenticated user who knows the current password can continue using `ChangePasswordAsync`. The existing three-call password-reset/grant API remains compatible and shares Haley's proof engine.

## Lifetimes and delivery boundaries

| Setting under `Haley:Identity:Server:Verification` | Default | Meaning |
| --- | --- | --- |
| CodeValiditySeconds | 300 | Default numeric OTP lifetime |
| MaximumCodeValiditySeconds | 3600 | Upper limit for requested numeric-code lifetime, at most one hour |
| ActivationLinkSeconds | 86400 | Default email-verification/onboarding token lifetime |
| PasswordResetSeconds | 1800 | Default reset-token lifetime and legacy reset-grant lifetime |
| LinkProofSeconds | 900 | Default email-login token lifetime |
| MaximumTokenValiditySeconds | 604800 | Upper limit for requested opaque-token lifetime; configurable up to 30 days |

A request must specify at least 60 seconds and no more than the applicable maximum. Use opaque tokens for multi-day invitations. Existing database verification policies govern attempt and resend limits; consumed, replaced, expired and exhausted challenges cannot be reused. Only hashes are persisted, including the optional context; proof material is returned only on issuance. No SQL migration is required for these workflows.
