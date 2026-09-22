namespace Haley.Abstractions;
public interface IIdentityRecoveryStore
{
    ValueTask<bool> CreateVerificationChallengeAsync(CreateVerificationChallengeCommand command, CancellationToken cancellationToken);
    ValueTask<StoredVerificationChallenge?> FindVerificationChallengeAsync(Guid challengeId, CancellationToken cancellationToken);
    ValueTask<bool> CompleteVerificationAsync(CompleteVerificationCommand command, CancellationToken cancellationToken);
    ValueTask<StoredPasswordResetSubject?> FindPasswordResetSubjectAsync(string channel, string destinationNormalized, CancellationToken cancellationToken);
    ValueTask<StoredPasswordResetCredential?> FindPasswordResetGrantCredentialAsync(Guid grantId, Guid clientId, DateTimeOffset evaluatedAt, CancellationToken cancellationToken);
    ValueTask<bool> ConsumePasswordResetGrantAsync(CompletePasswordResetCommand command, CancellationToken cancellationToken);
}
