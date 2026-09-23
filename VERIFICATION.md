# Verification workflows

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
