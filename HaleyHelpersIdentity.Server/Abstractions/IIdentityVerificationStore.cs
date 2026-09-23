namespace Haley.Abstractions;

/// <summary>Atomic challenge actions and their account/contact snapshots.</summary>
public interface IIdentityVerificationStore
{
    ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(string email, CancellationToken cancellationToken);
    ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(Guid userId, byte[] destinationHash, CancellationToken cancellationToken);
    ValueTask<bool> ReleaseExpiredLoginProtectionAsync(Guid userId, DateTimeOffset evaluatedAt, CancellationToken cancellationToken);
    ValueTask<bool> CreateVerificationChallengeAsync(CreateVerificationChallengeCommand command, CancellationToken cancellationToken);
    ValueTask<StoredVerificationChallenge?> FindVerificationChallengeAsync(Guid challengeId, CancellationToken cancellationToken);
    ValueTask<bool> CompletePasswordlessVerificationAsync(CompletePasswordlessVerificationCommand command, CancellationToken cancellationToken);
    ValueTask<bool> CompleteIdentityVerificationAsync(CompleteIdentityVerificationCommand command,
        Func<PasswordHash, bool> isReusedPassword, CancellationToken cancellationToken);
    ValueTask<bool> RecordLoginAttemptAndApplyProtectionAsync(LoginAttemptCommand command, int maximumFailedAttempts,
        int lockoutSeconds, CancellationToken cancellationToken);
}
