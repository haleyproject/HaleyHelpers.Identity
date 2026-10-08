using Haley.Abstractions;
using Haley.Models;

namespace Haley.Identity.Tests;

internal sealed class TotpLoginStore : IIdentityVerificationStore, IIdentityMfaStore
{
    private readonly object _gate = new();
    private readonly HashSet<string> _recovery = [];
    public StoredVerificationSubject? Subject { get; set; }
    public StoredMfaMethod? Method { get; set; }
    public List<LoginAttemptCommand> Attempts { get; } = [];
    public bool UnlockExpired { get; set; }
    public int MaximumAttempts { get; private set; }
    public int VerificationReads { get; private set; }
    public Action? OnConsumption { get; set; }
    public void AddRecovery(byte[] hash) => _recovery.Add(Convert.ToHexString(hash));

    public ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(string email, CancellationToken cancellationToken)
    {
        VerificationReads++;
        return ValueTask.FromResult(Subject?.Email == email ? Subject : null);
    }
    public ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(Guid userId, byte[] destinationHash, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> ReleaseExpiredLoginProtectionAsync(Guid userId, DateTimeOffset at, CancellationToken cancellationToken)
    {
        if (UnlockExpired && Subject is not null) Subject = Subject with { Identity = Subject.Identity with { Status = IdentityStatus.Active } };
        return ValueTask.FromResult(UnlockExpired);
    }
    public ValueTask<bool> RecordLoginAttemptAndApplyProtectionAsync(LoginAttemptCommand command, int maximumFailedAttempts,
        int lockoutSeconds, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Attempts.Add(command); MaximumAttempts = maximumFailedAttempts;
            if (Subject is not null && Attempts.Count(item => item.Outcome == "invalid_credential") >= maximumFailedAttempts)
                Subject = Subject with { Identity = Subject.Identity with { Status = IdentityStatus.Locked } };
        }
        return ValueTask.FromResult(false);
    }
    public ValueTask<IReadOnlyCollection<MfaMethodInfo>> ListMfaMethodsAsync(Guid userId, CancellationToken cancellationToken) =>
        ValueTask.FromResult<IReadOnlyCollection<MfaMethodInfo>>(Method is null ? [] : [Method.Method]);
    public ValueTask<StoredMfaMethod?> FindMfaMethodAsync(Guid methodId, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Method?.Method.MethodId == methodId ? Method : null);
    public ValueTask<bool> TouchMfaMethodAsync(Guid methodId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (Method is null || Method.Method.MethodId != methodId || Method.Method.LastUsedAt >= now) return ValueTask.FromResult(false);
            Method = Method with { Method = Method.Method with { LastUsedAt = now } };
            OnConsumption?.Invoke();
            return ValueTask.FromResult(true);
        }
    }
    public ValueTask<bool> ConsumeRecoveryCodeAsync(Guid userId, byte[] hash, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate) return ValueTask.FromResult(_recovery.Remove(Convert.ToHexString(hash)));
    }
    public ValueTask<bool> CreateVerificationChallengeAsync(CreateVerificationChallengeCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<StoredVerificationChallenge?> FindVerificationChallengeAsync(Guid challengeId, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CompletePasswordlessVerificationAsync(CompletePasswordlessVerificationCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CompleteIdentityVerificationAsync(CompleteIdentityVerificationCommand command, Func<PasswordHash, bool> predicate, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CreateMfaMethodAsync(CreateMfaMethodCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CreateMfaEnrollmentAsync(CreateMfaEnrollmentCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<StoredMfaEnrollment?> FindMfaEnrollmentAsync(byte[] ticketHash, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> FailMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CompleteMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> RetireMfaMethodAsync(Guid userId, Guid methodId, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> ConfirmMfaMethodAsync(Guid methodId, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> ReplaceRecoveryCodesAsync(Guid userId, IReadOnlyCollection<byte[]> hashes, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
}
