namespace Haley.Models;

/// <summary>Email verification alone does not activate an account. Only passwordless login returns a session.</summary>
public sealed record IdentityVerificationCompletion(Guid UserId, VerificationPurpose Purpose, bool EmailVerified,
    IdentityStatus AccountStatus, OpaqueSession? Session = null);
