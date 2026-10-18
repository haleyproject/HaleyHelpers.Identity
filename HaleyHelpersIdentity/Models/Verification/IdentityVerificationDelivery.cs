using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Trusted-backend delivery material, returned once. The application owns delivery and link construction.</summary>
public sealed record IdentityVerificationDelivery(Guid ChallengeId,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationPurpose>))] VerificationPurpose Purpose,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationProofKind>))] VerificationProofKind ProofKind,
    string Destination, string Verifier, DateTimeOffset ExpiresAt, DateTimeOffset ResendAllowedAt);
