namespace Haley.Models;

/// <summary>Verification and recovery eligibility of the specified current email contact.</summary>
public sealed record EmailVerificationInfo(Guid UserId, string Email, DateTimeOffset? VerifiedAt, bool RecoveryEnabled)
{
    public bool IsVerified => VerifiedAt is not null;
}
