namespace Haley.Abstractions;
public interface IIdentityMfaStore
{
    ValueTask<IReadOnlyCollection<MfaMethodInfo>> ListMfaMethodsAsync(Guid userId, CancellationToken cancellationToken);
    ValueTask<bool> CreateMfaMethodAsync(CreateMfaMethodCommand command, CancellationToken cancellationToken);
    ValueTask<bool> CreateMfaEnrollmentAsync(CreateMfaEnrollmentCommand command, CancellationToken cancellationToken);
    ValueTask<StoredMfaMethod?> FindMfaMethodAsync(Guid methodId, CancellationToken cancellationToken);
    ValueTask<StoredMfaEnrollment?> FindMfaEnrollmentAsync(byte[] ticketHash, CancellationToken cancellationToken);
    ValueTask<bool> FailMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<bool> CompleteMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<bool> RetireMfaMethodAsync(Guid userId, Guid methodId, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<bool> ConfirmMfaMethodAsync(Guid methodId, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<bool> TouchMfaMethodAsync(Guid methodId, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<bool> ReplaceRecoveryCodesAsync(Guid userId, IReadOnlyCollection<byte[]> codeHashes, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<bool> ConsumeRecoveryCodeAsync(Guid userId, byte[] codeHash, DateTimeOffset now, CancellationToken cancellationToken);
}
