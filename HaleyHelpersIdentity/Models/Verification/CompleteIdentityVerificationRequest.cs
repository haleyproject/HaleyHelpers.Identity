namespace Haley.Models;

/// <summary>Complete the bound action. NewPassword is required for PasswordReset and optional for Onboarding.
/// MFA fields apply only to PasswordlessLogin. Never place this payload in a query string.</summary>
public sealed record CompleteIdentityVerificationRequest(Guid ChallengeId, VerificationPurpose Purpose, string Verifier,
    VerificationProofKind ProofKind = VerificationProofKind.OpaqueToken, string? Context = null, string? NewPassword = null,
    MfaKind? MfaKind = null, Guid? MfaMethodId = null, string? MfaCode = null);
