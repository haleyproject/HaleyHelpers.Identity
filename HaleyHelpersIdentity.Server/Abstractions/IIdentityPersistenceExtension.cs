namespace Haley.Abstractions;

/// <summary>Owner-specific writes participate in the shared store's existing transaction.</summary>
public interface IIdentityPersistenceExtension
{
    ValueTask<bool> IsApplicationActiveAsync(Guid applicationId, DbExecutionLoad load) => ValueTask.FromResult(true);
    ValueTask AfterOpaqueSessionCreatedAsync(long localSessionId, StartOpaqueSessionCommand command, DbExecutionLoad load) => ValueTask.CompletedTask;
    ValueTask<bool> CanUseOpaqueSessionAsync(Guid sessionId, string? ownerContext, DbExecutionLoad load) => ValueTask.FromResult(true);
    ValueTask BeforeAccountDeleteAsync(Guid userId, long localUserId, DbExecutionLoad load) => ValueTask.CompletedTask;
    ValueTask AfterPasswordChangeAsync(Guid userId, long localUserId, DateTimeOffset at, DbExecutionLoad load) => ValueTask.CompletedTask;
    ValueTask AfterAccountStatusChangeAsync(Guid userId, long localUserId, IdentityStatus status, string reasonCode, DateTimeOffset at, DbExecutionLoad load) => ValueTask.CompletedTask;
    ValueTask AfterMfaEnrollmentCreatedAsync(long methodId, CreateMfaEnrollmentCommand command, DbExecutionLoad load) => ValueTask.CompletedTask;
}
