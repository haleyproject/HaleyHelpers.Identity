using Haley.DAL;
using Haley.Internal;
using System.Text.Json;
using static Haley.Internal.IdentityFields;

namespace Haley.Services;

public sealed partial class IdentityStore
{
    public async ValueTask<IReadOnlyCollection<AccountEmailContact>> ListAccountEmailContactsAsync(Guid userId, CancellationToken cancellationToken)
    {
        var rows = await RowsAsync(IdentityAdministrationQueries.EmailContacts, Load(cancellationToken),
            ("@user", IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
        return rows.Select(row => new AccountEmailContact(ToGuid(row, "contact_uid"),
            Required<string>(row, "email"), OptionalUtc(row, "verified_at"), (Required<uint>(row, "contact_flags") & 2) == 2)).ToArray();
    }

    public async ValueTask<bool> SetEmailVerificationAsync(SetEmailVerificationCommand command, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityUserQueries.FIND_EMAIL_CONTACT_FOR_OVERRIDE, load,
                    (UID, IdentityDatabase.ToBinary(command.UserId)),
                    (CONTACT_UID, IdentityDatabase.ToBinary(command.ContactId))).ConfigureAwait(false);
                if (row is null) { transaction.Rollback(); return false; }
                var contactId = Required<long>(row, "local_contact_id");
                var userId = Required<long>(row, "local_user_id");
                var at = command.OccurredAt.UtcDateTime;
                if (command.IsVerified)
                {
                    await ExecAsync(IdentityUserQueries.OVERRIDE_EMAIL_VERIFICATION, load, (AT, at), (ID, contactId)).ConfigureAwait(false);
                    await ExecAsync(IdentityUserQueries.CLEAR_CONTACT_VERIFICATION_PENDING, load, (AT, at), (USER_ID, userId)).ConfigureAwait(false);
                }
                else
                {
                    await ExecAsync(IdentityAdministrationQueries.UnverifyEmail, load, ("@id", contactId)).ConfigureAwait(false);
                    await ExecAsync(IdentityUserQueries.MARK_CONTACT_VERIFICATION_PENDING, load, (AT, at), (USER_ID, userId)).ConfigureAwait(false);
                    await ExecAsync(IdentityAdministrationQueries.CancelEmailChallenges, load,
                        ("@user", IdentityDatabase.ToBinary(command.UserId)), ("@contact", contactId), ("@at", at)).ConfigureAwait(false);
                    await ExecAsync(IdentityAdministrationQueries.ExpireEmailGrants, load,
                        ("@user", IdentityDatabase.ToBinary(command.UserId)), ("@contact", contactId), ("@at", at)).ConfigureAwait(false);
                }
                await AddOutboxAsync(load, _settings.EventPrefix + (command.IsVerified
                    ? ".email.verification.overridden.v1" : ".email.verification.withdrawn.v1"), "user_account", command.UserId,
                    JsonSerializer.Serialize(new { userId = command.UserId, contactId = command.ContactId,
                        reasonCode = command.ReasonCode, operatorName = command.OperatorName,
                        wasVerified = HasValue(row, "verified_at"), isVerified = command.IsVerified }),
                    command.OccurredAt).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    public async ValueTask<AccountSessionPage> ListAccountSessionsAsync(Guid userId, bool activeOnly, int page,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        page = Math.Clamp(page, 1, 100000);
        var rows = await RowsAsync(IdentityAdministrationQueries.Sessions, Load(cancellationToken),
            ("@user", IdentityDatabase.ToBinary(userId)), ("@active", activeOnly ? 1 : 0), ("@at", now.UtcDateTime),
            ("@limit", 11), ("@offset", (page - 1) * 10)).ConfigureAwait(false);
        return new(rows.Take(10).Select(row => new AccountSessionInfo(ToGuid(row, "session_uid"), ToGuid(row, "user_uid"),
            OptionalGuid(row, "application_uid"), (IdentityRecordStatus)Required<int>(row, "status"),
            AsUtc(Required<DateTime>(row, "auth_time")), AsUtc(Required<DateTime>(row, "last_seen_at")),
            AsUtc(Required<DateTime>(row, "expires_at")), OptionalUtc(row, "ended_at"))).ToArray(), page, 10, rows.Count > 10);
    }

    public async ValueTask<bool> RevokeAccountSessionAsync(Guid sessionId, DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecAsync(IdentityAdministrationQueries.RevokeSession, Load(cancellationToken),
            ("@uid", IdentityDatabase.ToBinary(sessionId)), ("@at", now.UtcDateTime)).ConfigureAwait(false) == 1;
}
