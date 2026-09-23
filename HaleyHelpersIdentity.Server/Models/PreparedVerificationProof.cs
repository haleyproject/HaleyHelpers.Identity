namespace Haley.Models;

public sealed record PreparedVerificationProof(CreateVerificationChallengeCommand Challenge, string Code,
    string? Token, DateTimeOffset ResendAllowedAt);
