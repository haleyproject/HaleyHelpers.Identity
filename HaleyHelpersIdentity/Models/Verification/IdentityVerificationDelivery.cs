namespace Haley.Models;

/// <summary>Trusted-backend delivery material, returned once. The application owns delivery and link construction.</summary>
public sealed record IdentityVerificationDelivery(Guid ChallengeId, VerificationPurpose Purpose, VerificationProofKind ProofKind,
    string Destination, string Verifier, DateTimeOffset ExpiresAt, DateTimeOffset ResendAllowedAt);
