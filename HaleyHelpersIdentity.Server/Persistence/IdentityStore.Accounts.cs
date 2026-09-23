using System.Text.Json;
using Haley.DAL;
using Haley.Internal;
using static Haley.Internal.IdentityFields;

namespace Haley.Services;

public sealed partial class IdentityStore
{
    public async ValueTask<UserIdentity?> FindAccountByEmailAsync(string email, CancellationToken cancellationToken)
    {
        var rows = await RowsAsync(IdentityAccountQueries.FindEmail, Load(cancellationToken), ("@email", email)).ConfigureAwait(false);
        return rows.Count == 1 ? ToUser(rows.Single()) : null;
    }

    public async ValueTask<UserIdentity?> EnsureAccountAsync(EnsureAccountCommand command, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await EnsureAccountRowAsync(command, true, load).ConfigureAwait(false);
                if (row is null) { transaction.Rollback(); return null; }
                transaction.Commit();
                return ToUser(row);
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    private async ValueTask<DbRow?> EnsureAccountRowAsync(EnsureAccountCommand command, bool createIfMissing, DbExecutionLoad load)
    {
        var rows = await RowsAsync(IdentityAccountQueries.FindEmailForUpdate, load, ("@email", command.Email)).ConfigureAwait(false);
        if (rows.Count > 1) return null;
        var row = rows.SingleOrDefault();
        if (row is null && !createIfMissing) return null;
        if (row is null)
        {
            var localId = await ScalarAsync<long?>(IdentityAccountQueries.InsertAccount, load,
                ("@uid", IdentityDatabase.ToBinary(command.UserId)), ("@email", command.Email),
                ("@display", command.DisplayName), ("@status", (int)command.InitialStatus), ("@at", command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
            if (localId is not null)
            {
                if (await ExecAsync(IdentityAccountQueries.InsertContact, load,
                    ("@uid", IdentityDatabase.ToBinary(command.ContactId)), ("@user", localId.Value),
                    ("@email", command.Email), ("@at", command.CreatedAt.UtcDateTime)).ConfigureAwait(false) != 1) return null;
                await AddOutboxAsync(load, _settings.EventPrefix + ".user.created.v2", "user_account", command.UserId,
                    JsonSerializer.Serialize(new { userId = command.UserId, status = (int)command.InitialStatus }),
                    command.CreatedAt).ConfigureAwait(false);
            }
            rows = await RowsAsync(IdentityAccountQueries.FindEmailForUpdate, load, ("@email", command.Email)).ConfigureAwait(false);
            if (rows.Count != 1) return null;
            row = rows.Single();
        }
        if (command.SourceHash is not null)
        {
            await ExecAsync(IdentityAccountQueries.InsertOrigin, load,
                ("@user", Required<long>(row, "local_user_id")),
                ("@application", IdentityDatabase.ToBinary(command.ApplicationId)),
                ("@hash", command.SourceHash), ("@at", command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
            var linked = await RowAsync(IdentityAccountQueries.FindOrigin, load,
                ("@application", IdentityDatabase.ToBinary(command.ApplicationId)), ("@hash", command.SourceHash)).ConfigureAwait(false);
            if (linked is null || ToGuid(linked, "user_uid") != ToGuid(row, "user_uid")) return null;
        }
        return row;
    }

    public async ValueTask<bool> StartOpaqueSessionAsync(StartOpaqueSessionCommand command, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var completed = await StartOpaqueSessionAsync(command, load).ConfigureAwait(false);
                if (completed) transaction.Commit(); else transaction.Rollback();
                return completed;
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    private async ValueTask<bool> StartOpaqueSessionAsync(StartOpaqueSessionCommand command, DbExecutionLoad load)
    {
        foreach (var extension in _extensions)
            if (!await extension.IsApplicationActiveAsync(command.Account.ApplicationId, load).ConfigureAwait(false))
            { return false; }
        var row = command.AuthenticatedUserId is Guid subject
            ? await RowAsync(IdentityAccountQueries.FindUserForUpdate, load, ("@uid", IdentityDatabase.ToBinary(subject))).ConfigureAwait(false)
            : await EnsureAccountRowAsync(command.Account, command.CreateIfMissing, load).ConfigureAwait(false);
        if (row is null || ParseStatus(Required<int>(row, "status")) != IdentityStatus.Active)
        { return false; }
        var userId = Required<long>(row, "local_user_id");
        if (command.ExpectedCredentialId is not null)
        {
            var current = await RowAsync(IdentityAccountQueries.FindCurrentCredential, load, ("@user", userId)).ConfigureAwait(false);
            if (current is null || Required<long>(current, "id") != command.ExpectedCredentialId)
            { return false; }
        }
        var localSessionId = await CreateSessionAsync(new(command.SessionId, userId, command.Account.ApplicationId, IdentitySessionKind.Opaque,
            command.ExpiresAt, command.Account.CreatedAt, command.AuthenticationMethods), load).ConfigureAwait(false);
        await ExecAsync(IdentityAccountQueries.InsertSessionToken, load,
            ("@session", localSessionId), ("@hash", command.TokenHash)).ConfigureAwait(false);
        foreach (var extension in _extensions)
            await extension.AfterOpaqueSessionCreatedAsync(localSessionId, command, load).ConfigureAwait(false);
        await AddOutboxAsync(load, _settings.EventPrefix + ".session.started.v1", "user_session", command.SessionId,
            JsonSerializer.Serialize(new { userId = ToGuid(row, "user_uid"), sessionId = command.SessionId,
                clientId = command.Account.ApplicationId, authenticationMethods = command.AuthenticationMethods }),
            command.Account.CreatedAt).ConfigureAwait(false);

        return true;

    }

    public async ValueTask<SessionValidation?> ValidateOpaqueSessionAsync(Guid applicationId, byte[] tokenHash,
        DateTimeOffset at, CancellationToken cancellationToken, string? ownerContext = null)
    {
        var row = await RowAsync(IdentityAccountQueries.ValidateSession, Load(cancellationToken),
            ("@application", IdentityDatabase.ToBinary(applicationId)), ("@hash", tokenHash), ("@at", at.UtcDateTime)).ConfigureAwait(false);
        if (row is null) return null;
        var sessionId = ToGuid(row, "session_uid");
        foreach (var extension in _extensions)
            if (!await extension.CanUseOpaqueSessionAsync(sessionId, ownerContext, Load(cancellationToken)).ConfigureAwait(false)) return null;
        return new(sessionId, AsUtc(Required<DateTime>(row, "expires_at")));
    }

    public async ValueTask<bool> RevokeOpaqueSessionAsync(Guid applicationId, byte[] tokenHash,
        DateTimeOffset at, CancellationToken cancellationToken) =>
        await ExecAsync(IdentityAccountQueries.RevokeSession, Load(cancellationToken),
            ("@application", IdentityDatabase.ToBinary(applicationId)), ("@hash", tokenHash), ("@at", at.UtcDateTime)).ConfigureAwait(false) > 0;

    public async ValueTask<bool> SetCredentialAsync(SetCredentialCommand command,
        Func<PasswordHash, bool> isReusedPassword, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var completed = await SetCredentialAsync(command, isReusedPassword, load).ConfigureAwait(false);
                if (completed) transaction.Commit(); else transaction.Rollback();
                return completed;
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    private async ValueTask<bool> SetCredentialAsync(SetCredentialCommand command, Func<PasswordHash, bool> isReusedPassword, DbExecutionLoad load)
    {
        var current = await RowAsync(IdentityAccountQueries.CurrentCredentialByUser, load,
            ("@uid", IdentityDatabase.ToBinary(command.UserId))).ConfigureAwait(false);
        if (current is null) { return false; }
        var localUserId = Required<long>(current, "local_user_id");
        var hasCredential = HasValue(current, "local_credential_id");
        if (command.ExpectedCredentialId is not null &&
            (!hasCredential || Required<long>(current, "local_credential_id") != command.ExpectedCredentialId))
        { return false; }
        var history = await RowsAsync(IdentityAccountQueries.PasswordHistory, load,
            ("@user", localUserId), ("@count", Math.Clamp(_settings.PasswordHistoryCount, 0, 100))).ConfigureAwait(false);
        if ((hasCredential && isReusedPassword(new(Required<byte[]>(current, "secret_hash"),
                Required<string>(current, "algorithm"), OptionalString(current, "params") ?? string.Empty))) ||
            history.Any(row => isReusedPassword(new(Required<byte[]>(row, "secret_hash"),
                Required<string>(row, "algorithm"), OptionalString(row, "params") ?? string.Empty))))
        { return false; }
        if (hasCredential)
        {
            if (!await ReplacePasswordAsync(load, current, localUserId, Required<long>(current, "local_credential_id"),
                command.UserId, command.CredentialId, command.Password.Value, command.Password.Algorithm,
                command.Password.ParametersPayload, command.RequirePasswordChange, command.ChangedAt,
                _settings.EventPrefix + ".password.changed.v1", JsonSerializer.Serialize(new { userId = command.UserId })).ConfigureAwait(false))
            { return false; }
        }
        else
        {
            await ExecAsync(IdentityUserQueries.INSERT_CREDENTIAL, load,
                (CREDENTIAL_UID, IdentityDatabase.ToBinary(command.CredentialId)), (USER_ID, localUserId),
                (SECRET_HASH, command.Password.Value), (ALGORITHM, command.Password.Algorithm),
                (PARAMS, command.Password.ParametersPayload), (CREATED_AT, command.ChangedAt.UtcDateTime)).ConfigureAwait(false);
            await ExecAsync(IdentityUserQueries.SET_PASSWORD_CHANGE_REQUIRED, load,
                (REQUIRED, command.RequirePasswordChange ? 1 : 0), (AT, command.ChangedAt.UtcDateTime), (USER_ID, localUserId)).ConfigureAwait(false);
            await ExecAsync(IdentityUserQueries.REVOKE_SESSIONS_AFTER_PASSWORD_CHANGE, load,
                (AT, command.ChangedAt.UtcDateTime), (USER_ID, localUserId)).ConfigureAwait(false);
            foreach (var extension in _extensions)
                await extension.AfterPasswordChangeAsync(command.UserId, localUserId, command.ChangedAt, load).ConfigureAwait(false);
            await AddOutboxAsync(load, _settings.EventPrefix + ".password.changed.v1", "user_account", command.UserId,
                JsonSerializer.Serialize(new { userId = command.UserId }), command.ChangedAt).ConfigureAwait(false);
        }

        return true;

    }
}
