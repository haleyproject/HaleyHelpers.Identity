using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Complete the bound action. NewPassword is required for PasswordReset and optional for Onboarding.
/// MFA fields apply only to PasswordlessLogin. Never place this payload in a query string.</summary>
public sealed record InspectIdentityVerificationRequest(Guid ChallengeId,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationPurpose>))] VerificationPurpose Purpose, string Verifier,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationProofKind>))] VerificationProofKind ProofKind = VerificationProofKind.OpaqueToken,
    string? Context = null);
