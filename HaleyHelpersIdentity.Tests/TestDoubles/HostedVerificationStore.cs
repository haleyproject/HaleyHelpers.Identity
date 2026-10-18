using Haley.Abstractions;
using Haley.Models;
using Haley.Services;

namespace Haley.Tests;

internal sealed class HostedVerificationStore : IIdentityVerificationStore
{
    private readonly object _gate = new();
    public StoredVerificationSubject Subject { get; set; } = new(new(Guid.NewGuid(), "Recipient", IdentityStatus.Pending,
        "recipient@example.test", DateTimeOffset.UtcNow, null), Guid.NewGuid(), "recipient@example.test", null, false, null);
    public StoredVerificationChallenge? Challenge { get; private set; }
    public int Completions { get; private set; }
    public int Reads { get; private set; }
    public bool CanCreateChallenges { get; set; } = true;
    public ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(string email, CancellationToken ct) =>
        ValueTask.FromResult<StoredVerificationSubject?>(email == Subject.Email ? Subject : null);
    public ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(Guid userId, byte[] destinationHash, CancellationToken ct) =>
        ValueTask.FromResult<StoredVerificationSubject?>(userId == Subject.Identity.UserId && destinationHash.SequenceEqual(VerificationProofService.Hash(Subject.Email)) ? Subject : null);
    public ValueTask<bool> ReleaseExpiredLoginProtectionAsync(Guid userId, DateTimeOffset at, CancellationToken ct) => ValueTask.FromResult(false);
    public ValueTask<bool> CreateVerificationChallengeAsync(CreateVerificationChallengeCommand command, CancellationToken ct)
    {
        if (!CanCreateChallenges) return ValueTask.FromResult(false);
        Challenge = new(1, command.ChallengeId, command.ApplicationId, command.SubjectId, command.Purpose, command.ContextHash,
            IdentityRecordStatus.Pending, 0, 5, 60, command.CodeHash, command.CodeAlgorithm, command.CodeParameters,
            command.CodeExpiresAt, command.LinkHash, command.NotBefore, command.ExpiresAt, command.DestinationHash);
        return ValueTask.FromResult(true);
    }
    public ValueTask<StoredVerificationChallenge?> FindVerificationChallengeAsync(Guid id, CancellationToken ct)
    { Reads++; return ValueTask.FromResult(Challenge?.ChallengeId == id ? Challenge : null); }
    public ValueTask<bool> CompletePasswordlessVerificationAsync(CompletePasswordlessVerificationCommand command, CancellationToken ct)
    {
        lock (_gate)
        {
            if (Challenge is null || Challenge.Status != IdentityRecordStatus.Pending || Challenge.Attempts != command.ExpectedAttempts) return ValueTask.FromResult(false);
            Challenge = Challenge with { Attempts = Challenge.Attempts + 1 };
            return ValueTask.FromResult(false);
        }
    }
    public ValueTask<bool> CompleteIdentityVerificationAsync(CompleteIdentityVerificationCommand command, Func<PasswordHash, bool> reused, CancellationToken ct)
    {
        lock (_gate)
        {
            if (Challenge is null || !VerificationProofService.IsPending(Challenge, command.CompletedAt)) return ValueTask.FromResult(false);
            Challenge = Challenge with { Status = IdentityRecordStatus.Retired };
            Subject = Subject with { VerifiedAt = command.CompletedAt, RecoveryEnabled = true,
                Identity = Subject.Identity with { Status = command.Purpose == VerificationPurpose.Onboarding ? IdentityStatus.Active : Subject.Identity.Status } };
            Completions++;
            return ValueTask.FromResult(true);
        }
    }
    public ValueTask<bool> RecordLoginAttemptAndApplyProtectionAsync(LoginAttemptCommand command, int maximum, int seconds, CancellationToken ct) => ValueTask.FromResult(false);
}
