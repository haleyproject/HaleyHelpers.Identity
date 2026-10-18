using Haley.Abstractions;
using Haley.Models;

namespace Haley.Identity.Tests;

internal sealed class TotpLoginStore : IIdentityVerificationStore, IIdentityMfaStore
{
    private readonly object _gate = new();
    private readonly HashSet<string> _recovery = [];
    public StoredVerificationSubject? Subject { get; set; }
    public StoredMfaMethod? Method { get; set; }
    public List<StoredMfaMethod> AdditionalMethods { get; } = [];
    public StoredMfaEnrollment? Enrollment { get; set; }
    public int EnrollmentFailures { get; private set; }
    public List<LoginAttemptCommand> Attempts { get; } = [];
    public bool UnlockExpired { get; set; }
    public int MaximumAttempts { get; private set; }
    public int VerificationReads { get; private set; }
    public Action? OnConsumption { get; set; }
    public Exception? RecoveryFailure { get; set; }
    public Func<Guid, CancellationToken, ValueTask<int>>? Pruning { get; set; }
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
        ValueTask.FromResult<IReadOnlyCollection<MfaMethodInfo>>(
            (Method is null ? [] : new[] { Method.Method }).Concat(AdditionalMethods.Select(method => method.Method)).ToArray());
    public ValueTask<StoredMfaMethod?> FindMfaMethodAsync(Guid methodId, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Method?.Method.MethodId == methodId ? Method
            : AdditionalMethods.FirstOrDefault(method => method.Method.MethodId == methodId));
    public ValueTask<bool> TouchMfaMethodAsync(Guid methodId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var main = Method?.Method.MethodId == methodId;
            var index = AdditionalMethods.FindIndex(method => method.Method.MethodId == methodId);
            var method = main ? Method : index >= 0 ? AdditionalMethods[index] : null;
            if (method is null || method.Method.Status != IdentityRecordStatus.Active || method.Method.LastUsedAt >= now)
                return ValueTask.FromResult(false);
            var updated = method with { Method = method.Method with { LastUsedAt = now } };
            if (main) Method = updated;
            else AdditionalMethods[index] = updated;
            OnConsumption?.Invoke();
            return ValueTask.FromResult(true);
        }
    }
    public ValueTask<bool> ConsumeRecoveryCodeAsync(Guid userId, byte[] hash, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (RecoveryFailure is not null) throw RecoveryFailure;
        lock (_gate) return ValueTask.FromResult(_recovery.Remove(Convert.ToHexString(hash)));
    }
    public ValueTask<bool> CreateVerificationChallengeAsync(CreateVerificationChallengeCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<StoredVerificationChallenge?> FindVerificationChallengeAsync(Guid challengeId, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CompletePasswordlessVerificationAsync(CompletePasswordlessVerificationCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CompleteIdentityVerificationAsync(CompleteIdentityVerificationCommand command, Func<PasswordHash, bool> predicate, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CreateMfaMethodAsync(CreateMfaMethodCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> CreateMfaEnrollmentAsync(CreateMfaEnrollmentCommand command, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<StoredMfaEnrollment?> FindMfaEnrollmentAsync(byte[] ticketHash, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Enrollment);
    public ValueTask<bool> FailMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset at, CancellationToken cancellationToken)
    {
        EnrollmentFailures++;
        if (Enrollment is not null) Enrollment = Enrollment with { Attempts = Enrollment.Attempts + 1 };
        return ValueTask.FromResult(true);
    }
    public ValueTask<bool> CompleteMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> RetireMfaMethodAsync(Guid userId, Guid methodId, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<int> PruneUnusedMfaMethodsAsync(Guid userId, CancellationToken cancellationToken) =>
        Pruning?.Invoke(userId, cancellationToken) ?? throw new NotSupportedException();
    public ValueTask<bool> ConfirmMfaMethodAsync(Guid methodId, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask<bool> ReplaceRecoveryCodesAsync(Guid userId, IReadOnlyCollection<byte[]> hashes, DateTimeOffset at, CancellationToken cancellationToken) => throw new NotSupportedException();
}
