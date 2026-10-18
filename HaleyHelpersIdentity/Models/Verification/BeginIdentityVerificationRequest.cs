using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Issue a verifier for an existing email contact. ValiditySeconds is bounded by server policy.
/// Context is optional application state that must be repeated exactly at completion.</summary>
public sealed record BeginIdentityVerificationRequest(string Email,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationPurpose>))] VerificationPurpose Purpose,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationProofKind>))] VerificationProofKind ProofKind = VerificationProofKind.OpaqueToken,
    int? ValiditySeconds = null, string? Context = null);
