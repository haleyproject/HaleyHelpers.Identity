using System.Text.Json;
using Haley.DAL;
using Haley.Internal;
namespace Haley.Services;
public sealed partial class IdentityStore
{
    /// <summary>Writes the base session inside the caller's transaction. The owner appends protocol state before committing.</summary>
    public async ValueTask<long> CreateSessionAsync(CreateSessionCommand command, DbExecutionLoad load)
    {
        if (command.Kind is not (IdentitySessionKind.Opaque or IdentitySessionKind.OwnerManaged) || (command.Kind == IdentitySessionKind.Opaque && command.ApplicationId is null))
            throw new ArgumentException("A valid session protocol and application binding are required.", nameof(command));
        var id = await ScalarAsync<long>(IdentityAccountQueries.InsertSession, load,
            ("@uid", IdentityDatabase.ToBinary(command.SessionId)), ("@user", command.LocalUserId),
            ("@application", command.ApplicationId is null ? null : IdentityDatabase.ToBinary(command.ApplicationId.Value)),
            ("@kind", (int)command.Kind), ("@expires", command.ExpiresAt.UtcDateTime)).ConfigureAwait(false);
        await ExecAsync(IdentityAccountQueries.InsertSessionInfo, load,
            ("@session", id), ("@at", command.CreatedAt.UtcDateTime), ("@methods", JsonSerializer.Serialize(command.AuthenticationMethods)),
            ("@ip", command.IpHash), ("@agent", command.UserAgentHash), ("@device", command.DeviceHash)).ConfigureAwait(false);
        await ExecAsync(IdentityAccountQueries.TouchAccount, load,
            ("@at", command.CreatedAt.UtcDateTime), ("@user", command.LocalUserId)).ConfigureAwait(false);
        return id;
    }

    /// <summary>Owner events use the shared outbox within the owner's existing transaction.</summary>
    public ValueTask WriteOutboxAsync(DbExecutionLoad load, string eventType, string aggregateType,
        Guid aggregateId, string payload, DateTimeOffset occurredAt) =>
        AddOutboxAsync(load, eventType, aggregateType, aggregateId, payload, occurredAt);
}
