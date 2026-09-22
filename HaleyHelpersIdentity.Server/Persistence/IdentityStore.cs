using Haley.DAL;
using System.Globalization;
using System.Text.Json;
using Haley.Internal;
using Microsoft.Extensions.Options;
using static Haley.Internal.IdentityFields;

namespace Haley.Services;

/// <summary>Owns account persistence and transactions shared by standalone hosts and Kida.</summary>
public sealed partial class IdentityStore : DALUtilBase, IIdentityMfaStore, IIdentityCredentialStore, IIdentityRecoveryStore
{
    private readonly IIdentityUuidGenerator _uuidGenerator;
    private readonly IdentityServerOptions _settings;
    private readonly IReadOnlyList<IIdentityPersistenceExtension> _extensions;
    public IdentityStore(IAdapterGateway gateway, IOptions<IdentityServerOptions> options,
        IIdentityUuidGenerator uuidGenerator, IEnumerable<IIdentityPersistenceExtension>? extensions = null) : base(gateway, options.Value.Adapter)
    {
        _uuidGenerator = uuidGenerator;
        _settings = options.Value;
        _extensions = extensions?.ToArray() ?? [];
    }
    public async ValueTask<StoredUserCredential?> FindLocalCredentialAsync(
        string usernameNormalized,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(
            IdentityUserQueries.FIND_LOCAL_CREDENTIAL,
            Load(cancellationToken),
            (USERNAME, usernameNormalized)).ConfigureAwait(false);
        return row is null ? null : new(
            Required<long>(row, "local_user_id"),
            Required<long>(row, "local_credential_id"),
            ToGuid(row, "user_uid"),
            Required<string>(row, "display_name"),
            ParseStatus(Required<int>(row, "status")),
            OptionalString(row, "normalized"),
            AsUtc(Required<DateTime>(row, "created_at")),
            OptionalUtc(row, "last_auth_at"),
            Required<byte[]>(row, "secret_hash"),
            Required<string>(row, "algorithm"),
            OptionalString(row, "params"),
            HasFlag(row, "flags", 2));
    }


    public async ValueTask<UserIdentity?> FindUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        var row = await RowAsync(
            IdentityUserQueries.FIND_USER,
            Load(cancellationToken),
            (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
        return row is null ? null : ToUser(row);
    }


    public async ValueTask<UserProfile?> FindUserProfileAsync(Guid userId, CancellationToken cancellationToken)
    {
        var row = await RowAsync(
            IdentityUserQueries.FIND_USER_PROFILE,
            Load(cancellationToken),
            (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
        return row is null ? null : ToUserProfile(row);
    }


    public async ValueTask<bool> CreateLocalUserAsync(CreateLocalUserCommand input, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var localUserId = await ScalarAsync<long?>(IdentityUserQueries.INSERT_USER, load,
                    (UID, IdentityDatabase.ToBinary(input.UserId)),
                    (STATUS, (int?)(FormatStatus(input.Status))),
                    (USERNAME, input.UsernameNormalized),
                    (DISPLAY_NAME, input.DisplayName),
                    (FLAGS, input.RequirePasswordChange ? 3 : 1),
                    (CREATED_AT, input.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (localUserId is null)
                {
                    transaction.Rollback();
                    return false;
                }

                await ExecAsync(IdentityUserQueries.INSERT_CREDENTIAL, load,
                    (CREDENTIAL_UID, IdentityDatabase.ToBinary(input.CredentialId)),
                    (USER_ID, localUserId.Value),
                    (SECRET_HASH, input.SecretHash),
                    (ALGORITHM, input.Algorithm),
                    (PARAMS, input.ParametersPayload),
                    (CREATED_AT, input.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (input.EmailContactId is { } emailContactId)
                {
                    await ExecAsync(IdentityLifecycleQueries.INSERT_EMAIL_CONTACT, load,
                        (CONTACT_UID, IdentityDatabase.ToBinary(emailContactId)),
                        (USER_ID, localUserId.Value),
                        (EMAIL, input.UsernameNormalized),
                        (DISPLAY_NAME, input.UsernameNormalized),
                        (CREATED_AT, input.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                }
                await AddOutboxAsync(load, _settings.EventPrefix + ".user.created.v2", "user_account", input.UserId,
                    JsonSerializer.Serialize(new { userId = input.UserId, status = FormatStatus(input.Status) }), input.CreatedAt)
                    .ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> ChangePasswordAsync(
        ChangePasswordCommand input,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var current = await RowAsync(IdentityUserQueries.FIND_CREDENTIAL_FOR_CHANGE, load,
                    (CREDENTIAL_ID, input.LocalCredentialId),
                    (USER_ID, input.LocalUserId)).ConfigureAwait(false);
                if (current is null)
                {
                    transaction.Rollback();
                    return false;
                }

                var changed = await ReplacePasswordAsync(
                    load,
                    current,
                    input.LocalUserId,
                    input.LocalCredentialId,
                    input.UserId,
                    input.CredentialId,
                    input.SecretHash,
                    input.Algorithm,
                    input.ParametersPayload,
                    requirePasswordChange: false,
                    input.ChangedAt,
                    _settings.EventPrefix + ".password.changed.v1",
                    JsonSerializer.Serialize(new { userId = input.UserId })).ConfigureAwait(false);
                if (!changed)
                {
                    transaction.Rollback();
                    return false;
                }

                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> ResetUserPasswordAsync(
        ResetUserPasswordCommand input,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var current = await RowAsync(
                    IdentityUserQueries.FIND_CREDENTIAL_FOR_ADMIN_RESET,
                    load,
                    (UID, IdentityDatabase.ToBinary(input.UserId))).ConfigureAwait(false);
                if (current is null)
                {
                    transaction.Rollback();
                    return false;
                }

                var localUserId = Required<long>(current, "local_user_id");
                var localCredentialId = Required<long>(current, "local_credential_id");
                var changed = await ReplacePasswordAsync(
                    load,
                    current,
                    localUserId,
                    localCredentialId,
                    input.UserId,
                    input.CredentialId,
                    input.SecretHash,
                    input.Algorithm,
                    input.ParametersPayload,
                    input.RequirePasswordChange,
                    input.ChangedAt,
                    _settings.EventPrefix + ".password.reset.v1",
                    JsonSerializer.Serialize(new
                    {
                        userId = input.UserId,
                        requirePasswordChange = input.RequirePasswordChange,
                        reasonCode = input.ReasonCode,
                        actorReference = input.ActorReference
                    })).ConfigureAwait(false);
                if (!changed)
                {
                    transaction.Rollback();
                    return false;
                }

                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> UpdateUserProfileAsync(
        UpdateUserProfileCommand input,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var user = await RowAsync(
                    IdentityUserQueries.FIND_USER_FOR_PROFILE_UPDATE,
                    load,
                    (UID, IdentityDatabase.ToBinary(input.UserId))).ConfigureAwait(false);
                if (user is null)
                {
                    transaction.Rollback();
                    return false;
                }

                var localUserId = Required<long>(user, "local_user_id");
                await ExecAsync(IdentityUserQueries.UPDATE_PROFILE_DISPLAY_NAME, load,
                    (DISPLAY_NAME, input.DisplayName),
                    (MODIFIED_AT, input.ModifiedAt.UtcDateTime),
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.UPSERT_USER_PROFILE, load,
                    (USER_ID, localUserId),
                    (GIVEN_NAME, input.GivenName),
                    (FAMILY_NAME, input.FamilyName),
                    (PREFERRED_NAME, input.PreferredName),
                    (LOCALE, input.Locale),
                    (TIME_ZONE, input.TimeZone),
                    (AVATAR_URI, input.AvatarUri),
                    (MODIFIED_AT, input.ModifiedAt.UtcDateTime)).ConfigureAwait(false);
                await AddOutboxAsync(
                    load,
                    _settings.EventPrefix + ".profile.updated.v1",
                    "user_account",
                    input.UserId,
                    JsonSerializer.Serialize(new { userId = input.UserId }),
                    input.ModifiedAt).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask RecordLoginAttemptAsync(LoginAttemptCommand input, CancellationToken cancellationToken)
    {
        await ExecAsync(IdentitySessionQueries.INSERT_LOGIN_ATTEMPT, Load(cancellationToken),
            (USER_UID, DbBinary(input.UserId)),
            (HINT_HASH, input.LoginHintHash),
            (APPLICATION_UID, DbBinary(input.ApplicationId)),
            (OUTCOME, input.Outcome),
            (REASON_CODE, input.ReasonCode),
            (IP_HASH, input.IpHash),
            (USER_AGENT_HASH, input.UserAgentHash),
            (OCCURRED_AT, input.OccurredAt.UtcDateTime)).ConfigureAwait(false);
    }


    public async ValueTask<bool> RecordLoginAttemptAndApplyProtectionAsync(
        LoginAttemptCommand input,
        int maximumFailedAttempts,
        int lockoutSeconds,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var effectiveAttempt = input;
                var locked = false;
                if (input.UserId is not null &&
                    string.Equals(input.Outcome, "invalid_credential", StringComparison.Ordinal))
                {
                    var user = await RowAsync(IdentityUserQueries.FIND_STATUS_FOR_UPDATE, load,
                        (UID, IdentityDatabase.ToBinary(input.UserId.Value))).ConfigureAwait(false);
                    if (user is not null && ((IdentityRecordStatus)Required<int>(user, "status") == IdentityRecordStatus.Active))
                    {
                        var localUserId = Required<long>(user, "local_user_id");
                        var userUid = IdentityDatabase.ToBinary(input.UserId.Value);
                        var previousFailures = await ScalarAsync<long>(
                            IdentitySessionQueries.COUNT_FAILED_ATTEMPTS_SINCE_BOUNDARY,
                            load,
                            (USER_UID, userUid),
                            (USER_ID, localUserId)).ConfigureAwait(false);
                        if (previousFailures + 1 >= Math.Clamp(maximumFailedAttempts, 1, 100))
                        {
                            var expiresAt = input.OccurredAt.AddSeconds(Math.Clamp(lockoutSeconds, 60, 86_400));
                            await ExecAsync(IdentitySessionQueries.INSERT_AUTOMATIC_ACCOUNT_LOCK, load,
                                (USER_ID, localUserId),
                                (AT, input.OccurredAt.UtcDateTime),
                                (EXPIRES_AT, expiresAt.UtcDateTime)).ConfigureAwait(false);
                            await ExecAsync(IdentityUserQueries.UPDATE_STATUS, load,
                                (STATUS, (int?)(IdentityRecordStatus.Locked)),
                                (AT, input.OccurredAt.UtcDateTime),
                                (ID, localUserId)).ConfigureAwait(false);
                            await ExecAsync(IdentityUserQueries.REVOKE_ACTIVE_SESSIONS, load,
                                (AT, input.OccurredAt.UtcDateTime),
                                (USER_ID, localUserId)).ConfigureAwait(false);
                            foreach (var extension in _extensions)
                                await extension.AfterAccountStatusChangeAsync(input.UserId.Value, localUserId, IdentityStatus.Locked,
                                    "failed_login_threshold", input.OccurredAt, load).ConfigureAwait(false);
                            await AddOutboxAsync(
                                load,
                                _settings.EventPrefix + ".user.login.locked.v1",
                                "user_account",
                                input.UserId.Value,
                                JsonSerializer.Serialize(new
                                {
                                    userId = input.UserId.Value,
                                    reasonCode = "failed_login_threshold",
                                    maximumFailedAttempts = Math.Clamp(maximumFailedAttempts, 1, 100),
                                    expiresAt
                                }),
                                input.OccurredAt).ConfigureAwait(false);
                            effectiveAttempt = input with
                            {
                                Outcome = "locked",
                                ReasonCode = "failed_login_threshold"
                            };
                            locked = true;
                        }
                    }
                }

                await ExecAsync(IdentitySessionQueries.INSERT_LOGIN_ATTEMPT, load,
                    (USER_UID, DbBinary(effectiveAttempt.UserId)),
                    (HINT_HASH, effectiveAttempt.LoginHintHash),
                    (APPLICATION_UID, DbBinary(effectiveAttempt.ApplicationId)),
                    (OUTCOME, effectiveAttempt.Outcome),
                    (REASON_CODE, effectiveAttempt.ReasonCode),
                    (IP_HASH, effectiveAttempt.IpHash),
                    (USER_AGENT_HASH, effectiveAttempt.UserAgentHash),
                    (OCCURRED_AT, effectiveAttempt.OccurredAt.UtcDateTime)).ConfigureAwait(false);
                transaction.Commit();
                return locked;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> ReleaseExpiredLoginProtectionAsync(
        Guid userId,
        DateTimeOffset evaluatedAt,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var user = await RowAsync(IdentityUserQueries.FIND_STATUS_FOR_UPDATE, load,
                    (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
                if (user is null || !((IdentityRecordStatus)Required<int>(user, "status") == IdentityRecordStatus.Locked))
                {
                    transaction.Rollback();
                    return false;
                }

                var localUserId = Required<long>(user, "local_user_id");
                var released = await ExecAsync(IdentitySessionQueries.RELEASE_EXPIRED_ACCOUNT_LOCKS, load,
                    (USER_ID, localUserId),
                    (AT, evaluatedAt.UtcDateTime)).ConfigureAwait(false);
                if (released == 0)
                {
                    transaction.Rollback();
                    return false;
                }

                var remainingLocks = await ScalarAsync<long>(IdentitySessionQueries.COUNT_ACTIVE_ACCOUNT_LOCKS, load,
                    (USER_ID, localUserId),
                    (AT, evaluatedAt.UtcDateTime)).ConfigureAwait(false);
                if (remainingLocks > 0)
                {
                    transaction.Commit();
                    return false;
                }

                var activated = await ExecAsync(IdentityUserQueries.ACTIVATE_LOCKED_USER, load,
                    (AT, evaluatedAt.UtcDateTime),
                    (ID, localUserId)).ConfigureAwait(false) == 1;
                if (activated)
                {
                    await AddOutboxAsync(
                        load,
                        _settings.EventPrefix + ".user.login.lock.expired.v1",
                        "user_account",
                        userId,
                        JsonSerializer.Serialize(new { userId, reasonCode = "automatic_lock_expired" }),
                        evaluatedAt).ConfigureAwait(false);
                }
                transaction.Commit();
                return activated;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<IReadOnlyCollection<UserIdentity>> ListUsersAsync(
        UserSearchRequest request,
        CancellationToken cancellationToken)
    {
        var query = string.IsNullOrWhiteSpace(request.Query) ? null : request.Query.Trim();
        var queryUidLike = UidSearchPattern(query);
        var rows = await RowsAsync(IdentityUserQueries.LIST_USERS, Load(cancellationToken),
            (QUERY, query), (QUERY_LIKE, query is null ? null : $"%{query}%"),
            (QUERY_UID_LIKE, queryUidLike),
            (STATUS, (int?)(request.Status is null ? null : FormatStatus(request.Status.Value))),
            (AFTER_UID, DbBinary(request.AfterUserId)),
            (LIMIT, Math.Clamp(request.Limit, 1, 250))).ConfigureAwait(false);
        return rows.Select(ToUser).ToArray();
    }


    public async ValueTask<UserIdentityPage> ListUserPageAsync(
        UserPageRequest request,
        CancellationToken cancellationToken)
    {
        var load = Load(cancellationToken);
        var query = string.IsNullOrWhiteSpace(request.Query) ? null : request.Query.Trim();
        var queryLike = query is null ? null : $"%{query}%";
        var queryUidLike = UidSearchPattern(query);
        int? status = request.Status is null ? null : FormatStatus(request.Status.Value);
        var lookaheadLimit = checked(request.PageSize + 1);
        var rows = await RowsAsync(IdentityUserQueries.LIST_USER_PAGE, load,
            (QUERY, query), (QUERY_LIKE, queryLike), (QUERY_UID_LIKE, queryUidLike), (STATUS, (int?)(status)),
            (ACTIVITY, FormatActivity(request.Activity)),
            (SORT, FormatSort(request.Sort)),
            (LIMIT, lookaheadLimit),
            (OFFSET, checked((long)(request.Page - 1) * request.PageSize))).ConfigureAwait(false);
        var hasNext = rows.Count > request.PageSize;
        return new(rows.Take(request.PageSize).Select(ToUser).ToArray(), request.Page, request.PageSize, hasNext);
    }


    private static string? UidSearchPattern(string? query) =>
        query is null
            ? null
            : $"%{query.Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant()}%";


    public async ValueTask<bool> ChangeUserStatusAsync(
        Guid userId,
        IdentityStatus status,
        string reasonCode,
        DateTimeOffset changedAt,
        CancellationToken cancellationToken, IdentityStatus? expectedStatus = null)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityUserQueries.FIND_STATUS_FOR_UPDATE, load,
                    (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
                if (row is null)
                {
                    transaction.Rollback();
                    return false;
                }
                var localUserId = Required<long>(row, "local_user_id");
                var currentStatus = ParseStatus(Required<int>(row, "status"));
                if ((expectedStatus is not null && currentStatus != expectedStatus) ||
                    ((currentStatus == IdentityStatus.Retired) && status != IdentityStatus.Retired))
                {
                    transaction.Rollback();
                    return false;
                }

                await ExecAsync(IdentityUserQueries.UPDATE_STATUS, load,
                    (STATUS, (int?)(FormatStatus(status))), (AT, changedAt.UtcDateTime),
                    (ID, localUserId)).ConfigureAwait(false);
                if (status == IdentityStatus.Locked)
                {
                    await ExecAsync(IdentityUserQueries.INSERT_ACCOUNT_LOCK, load,
                        (USER_ID, localUserId), (REASON, reasonCode),
                        (AT, changedAt.UtcDateTime)).ConfigureAwait(false);
                }
                else if ((currentStatus == IdentityStatus.Locked))
                {
                    await ExecAsync(IdentityUserQueries.RELEASE_ACCOUNT_LOCK, load,
                        (AT, changedAt.UtcDateTime), (USER_ID, localUserId)).ConfigureAwait(false);
                }

                if (status != IdentityStatus.Active)
                {
                    await ExecAsync(IdentityUserQueries.REVOKE_ACTIVE_SESSIONS, load,
                        (AT, changedAt.UtcDateTime), (USER_ID, localUserId)).ConfigureAwait(false);
                }

                await AddOutboxAsync(load, _settings.EventPrefix + ".user.status.changed.v2", "user_account", userId,
                    JsonSerializer.Serialize(new
                    {
                        userId,
                        previousStatus = currentStatus,
                        status = FormatStatus(status),
                        reasonCode
                    }), changedAt).ConfigureAwait(false);
                foreach (var extension in _extensions)
                    await extension.AfterAccountStatusChangeAsync(userId, localUserId, status, reasonCode, changedAt, load).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> RestoreUserAsync(
        Guid userId,
        string reasonCode,
        DateTimeOffset restoredAt,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityUserQueries.FIND_STATUS_FOR_UPDATE, load,
                    (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
                if (row is null ||
                    !((IdentityRecordStatus)Required<int>(row, "status") == IdentityRecordStatus.Retired))
                {
                    transaction.Rollback();
                    return false;
                }

                var localUserId = Required<long>(row, "local_user_id");
                var changed = await ExecAsync(IdentityUserQueries.RESTORE_USER, load,
                    (AT, restoredAt.UtcDateTime),
                    (ID, localUserId)).ConfigureAwait(false);
                if (changed != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                await AddOutboxAsync(load, _settings.EventPrefix + ".user.restored.v1", "user_account", userId,
                    JsonSerializer.Serialize(new { userId, reasonCode }), restoredAt).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> PermanentlyDeleteUserAsync(
        Guid userId,
        string reasonCode,
        DateTimeOffset deletedAt,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityUserQueries.FIND_STATUS_FOR_UPDATE, load,
                    (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
                if (row is null ||
                    !((IdentityRecordStatus)Required<int>(row, "status") == IdentityRecordStatus.Retired))
                {
                    transaction.Rollback();
                    return false;
                }

                var localUserId = Required<long>(row, "local_user_id");
                foreach (var extension in _extensions)
                    await extension.BeforeAccountDeleteAsync(userId, localUserId, load).ConfigureAwait(false);
                var userUid = IdentityDatabase.ToBinary(userId);
                await AddOutboxAsync(load, _settings.EventPrefix + ".user.deleted.v1", "user_account", userId,
                    JsonSerializer.Serialize(new { userId, reasonCode, permanent = true }), deletedAt)
                    .ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.ANONYMIZE_LOGIN_ATTEMPTS, load,
                    (USER_UID, userUid)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.ANONYMIZE_VERIFICATION_CONSUMER, load,
                    (USER_UID, userUid)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_SUBJECT_VERIFICATION_GRANTS, load,
                    (USER_UID, userUid)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_SUBJECT_CHALLENGE_ATTEMPTS, load,
                    (USER_UID, userUid)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_SUBJECT_VERIFICATION_CHALLENGES, load,
                    (USER_UID, userUid)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_USER_SESSIONS, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_ACCOUNT_LOCKS, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_RECOVERY_CODES, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_MFA_METHODS, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_PASSWORD_HISTORY, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_CREDENTIALS, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_CONTACT_METHODS, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await ExecAsync(IdentityUserQueries.DELETE_USER_PROFILE, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                var deleted = await ExecAsync(IdentityUserQueries.DELETE_USER_ACCOUNT, load,
                    (ID, localUserId)).ConfigureAwait(false);
                if (deleted != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> RecordLoginEmailContactAsync(
        Guid userId,
        Guid contactId,
        string emailNormalized,
        DateTimeOffset recordedAt,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var user = await RowAsync(IdentityUserQueries.FIND_USER_FOR_LOGIN_EMAIL_CONTACT, load,
                    (UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
                if (user is null)
                {
                    transaction.Rollback();
                    return false;
                }

                var localUserId = Required<long>(user, "local_user_id");
                var existing = await RowAsync(IdentityUserQueries.FIND_ACTIVE_USER_EMAIL_CONTACT, load,
                    (USER_ID, localUserId)).ConfigureAwait(false);
                if (existing is not null)
                {
                    var matches = string.Equals(
                        Required<string>(existing, "normalized"),
                        emailNormalized,
                        StringComparison.Ordinal);
                    transaction.Commit();
                    return matches;
                }

                var inserted = await ExecAsync(IdentityUserQueries.INSERT_LOGIN_EMAIL_CONTACT, load,
                    (CONTACT_UID, IdentityDatabase.ToBinary(contactId)),
                    (USER_ID, localUserId),
                    (EMAIL, emailNormalized),
                    (CREATED_AT, recordedAt.UtcDateTime)).ConfigureAwait(false);
                if (inserted != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                await ExecAsync(IdentityUserQueries.MARK_CONTACT_VERIFICATION_PENDING, load,
                    (AT, recordedAt.UtcDateTime),
                    (USER_ID, localUserId)).ConfigureAwait(false);
                await AddOutboxAsync(
                    load,
                    _settings.EventPrefix + ".email.contact.recorded.v1",
                    "user_account",
                    userId,
                    JsonSerializer.Serialize(new { userId, contactId }),
                    recordedAt).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> OverrideEmailVerificationAsync(
        Guid userId,
        Guid contactId,
        string reasonCode,
        DateTimeOffset verifiedAt,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityUserQueries.FIND_EMAIL_CONTACT_FOR_OVERRIDE, load,
                    (UID, IdentityDatabase.ToBinary(userId)),
                    (CONTACT_UID, IdentityDatabase.ToBinary(contactId))).ConfigureAwait(false);
                if (row is null)
                {
                    transaction.Rollback();
                    return false;
                }

                if (HasValue(row, "verified_at"))
                {
                    transaction.Commit();
                    return true;
                }

                var localContactId = Required<long>(row, "local_contact_id");
                var localUserId = Required<long>(row, "local_user_id");
                var changed = await ExecAsync(IdentityUserQueries.OVERRIDE_EMAIL_VERIFICATION, load,
                    (AT, verifiedAt.UtcDateTime), (ID, localContactId)).ConfigureAwait(false);
                if (changed != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                await ExecAsync(IdentityUserQueries.CLEAR_CONTACT_VERIFICATION_PENDING, load,
                    (AT, verifiedAt.UtcDateTime), (USER_ID, localUserId)).ConfigureAwait(false);
                await AddOutboxAsync(load, _settings.EventPrefix + ".email.verification.overridden.v1", "user_account", userId,
                    JsonSerializer.Serialize(new { userId, contactId, reasonCode }), verifiedAt).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<UserLoginAttemptPage> ListUserLoginAttemptsAsync(
        UserLoginAttemptSearchRequest request,
        CancellationToken cancellationToken)
    {
        var load = Load(cancellationToken);
        var userUid = IdentityDatabase.ToBinary(request.UserId);
        var lookaheadLimit = checked(request.PageSize + 1);
        var rows = await RowsAsync(IdentityUserQueries.LIST_LOGIN_ATTEMPTS, load,
            (USER_UID, userUid), (LIMIT, lookaheadLimit),
            (OFFSET, checked((long)(request.Page - 1) * request.PageSize))).ConfigureAwait(false);
        var hasNext = rows.Count > request.PageSize;
        return new(
            rows.Take(request.PageSize).Select(row => new UserLoginAttemptInfo(
                Required<long>(row, "id"),
                ToGuid(row, "user_uid"),
                OptionalGuid(row, "application_uid"),
                Required<string>(row, "outcome"),
                OptionalString(row, "reason_code"),
                AsUtc(Required<DateTime>(row, "occurred_at"))))
                .ToArray(),
            request.Page,
            request.PageSize,
            hasNext);
    }


    private async ValueTask<bool> ReplacePasswordAsync(
        DbExecutionLoad load,
        DbRow current,
        long localUserId,
        long localCredentialId,
        Guid userId,
        Guid replacementCredentialId,
        byte[] secretHash,
        string algorithm,
        string parametersPayload,
        bool requirePasswordChange,
        DateTimeOffset changedAt,
        string eventType,
        string eventPayload)
    {
        await ExecAsync(IdentityUserQueries.INSERT_PASSWORD_HISTORY, load,
            (USER_ID, localUserId),
            (SECRET_HASH, Required<byte[]>(current, "secret_hash")),
            (ALGORITHM, Required<string>(current, "algorithm")),
            (PARAMS, OptionalString(current, "params")),
            (CREATED_AT, changedAt.UtcDateTime)).ConfigureAwait(false);
        var retired = await ExecAsync(IdentityUserQueries.RETIRE_CREDENTIAL, load,
            (AT, changedAt.UtcDateTime),
            (CREDENTIAL_ID, localCredentialId),
            (USER_ID, localUserId)).ConfigureAwait(false);
        if (retired != 1)
        {
            return false;
        }

        await ExecAsync(IdentityUserQueries.INSERT_CREDENTIAL, load,
            (CREDENTIAL_UID, IdentityDatabase.ToBinary(replacementCredentialId)),
            (USER_ID, localUserId),
            (SECRET_HASH, secretHash),
            (ALGORITHM, algorithm),
            (PARAMS, parametersPayload),
            (CREATED_AT, changedAt.UtcDateTime)).ConfigureAwait(false);
        await ExecAsync(IdentityUserQueries.SET_PASSWORD_CHANGE_REQUIRED, load,
            (REQUIRED, requirePasswordChange ? 1 : 0),
            (AT, changedAt.UtcDateTime),
            (USER_ID, localUserId)).ConfigureAwait(false);
        await ExecAsync(IdentityUserQueries.REVOKE_SESSIONS_AFTER_PASSWORD_CHANGE, load,
            (AT, changedAt.UtcDateTime),
            (USER_ID, localUserId)).ConfigureAwait(false);
        foreach (var extension in _extensions)
            await extension.AfterPasswordChangeAsync(userId, localUserId, changedAt, load).ConfigureAwait(false);
        await AddOutboxAsync(load, eventType, "user_account", userId, eventPayload, changedAt)
            .ConfigureAwait(false);
        return true;
    }


    private async ValueTask AddOutboxAsync(
        DbExecutionLoad load,
        string eventType,
        string aggregateType,
        Guid aggregateId,
        string payload,
        DateTimeOffset occurredAt)
    {
        var messageId = await ScalarAsync<long>(IdentityOutboxQueries.INSERT_MSG, load,
            (EVENT_UID, IdentityDatabase.ToBinary(_uuidGenerator.NewUuid7())),
            (AGGREGATE_UID, IdentityDatabase.ToBinary(aggregateId)),
            (OCCURRED_AT, occurredAt.UtcDateTime)).ConfigureAwait(false);
        await ExecAsync(IdentityOutboxQueries.INSERT_DATA, load,
            (MSG_ID, messageId), (EVENT_TYPE, eventType), (AGGREGATE_TYPE, aggregateType),
            (OCCURRED_AT, occurredAt.UtcDateTime), (PAYLOAD, payload)).ConfigureAwait(false);
    }


    private static UserIdentity ToUser(DbRow row) => new(
        ToGuid(row, "user_uid"), Required<string>(row, "display_name"),
        ParseStatus(Required<int>(row, "status")), OptionalString(row, "normalized"),
        AsUtc(Required<DateTime>(row, "created_at")), OptionalUtc(row, "last_auth_at"),
        HasFlag(row, "flags", 2));


    private static UserProfile ToUserProfile(DbRow row) => new(
        ToGuid(row, "user_uid"),
        Required<string>(row, "display_name"),
        OptionalString(row, "given_name"),
        OptionalString(row, "family_name"),
        OptionalString(row, "preferred_name"),
        OptionalString(row, "locale"),
        OptionalString(row, "time_zone"),
        OptionalString(row, "avatar_uri"),
        AsUtc(Required<DateTime>(row, "modified_at")));


    private static DbExecutionLoad Load(CancellationToken cancellationToken, ITransactionHandler? transaction = null) =>
        new(cancellationToken, transaction);


    private static T Required<T>(DbRow row, string key)
    {
        if (!row.TryGetValue(key, out var value) || value is null || value is DBNull)
            throw new InvalidDataException($"Database result did not contain required value '{key}'.");
        if (value is T typed) return typed;
        return (T)Convert.ChangeType(value, typeof(T), CultureInfo.InvariantCulture);
    }


    private static bool HasValue(DbRow row, string key)
    {
        if (!row.TryGetValue(key, out var value) || value is null || value is DBNull)
        {
            return false;
        }

        // Haley currently materializes some provider NULL values as an empty string.
        // Treat that representation as absent before converting nullable columns.
        return value is not string text || !string.IsNullOrWhiteSpace(text);
    }


    private static bool HasFlag(DbRow row, string key, long flag) =>
        (Required<long>(row, key) & flag) == flag;


    private static string? OptionalString(DbRow row, string key) => HasValue(row, key) ? Required<string>(row, key) : null;

    internal static DateTimeOffset? OptionalUtc(DbRow row, string key) => HasValue(row, key) ? AsUtc(Required<DateTime>(row, key)) : null;

    private static Guid ToGuid(DbRow row, string key) => IdentityDatabase.FromBinary(Required<byte[]>(row, key));

    private static Guid? OptionalGuid(DbRow row, string key) => HasValue(row, key) ? ToGuid(row, key) : null;

    private static object? DbBinary(Guid? value) => value is null ? null : IdentityDatabase.ToBinary(value.Value);


    private static IdentityStatus ParseStatus(int status) => (IdentityStatus)status is IdentityStatus.Pending or IdentityStatus.Active or IdentityStatus.Locked or IdentityStatus.Suspended or IdentityStatus.Retired
        ? (IdentityStatus)status
        : throw new InvalidDataException($"Unknown identity status value {status}.");


    private static int FormatStatus(IdentityStatus status) => (int)status;

    private static string FormatActivity(UserActivityFilter activity) => activity switch
    {
        UserActivityFilter.All => "all",
        UserActivityFilter.NeverLoggedIn => "never_logged_in",
        UserActivityFilter.HasLoggedIn => "has_logged_in",
        UserActivityFilter.PasswordChangeRequired => "password_change_required",
        _ => throw new ArgumentOutOfRangeException(nameof(activity))
    };


    private static string FormatSort(UserSortOrder sort) => sort switch
    {
        UserSortOrder.CreatedNewest => "created_newest",
        UserSortOrder.CreatedOldest => "created_oldest",
        UserSortOrder.LastLoginNewest => "last_login_newest",
        UserSortOrder.LastLoginOldest => "last_login_oldest",
        _ => throw new ArgumentOutOfRangeException(nameof(sort))
    };

    private static DateTimeOffset AsUtc(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Utc));


    public async ValueTask<IReadOnlyCollection<MfaMethodInfo>> ListMfaMethodsAsync(Guid userId, CancellationToken cancellationToken)
    {
        var rows = await RowsAsync(IdentityMfaQueries.LIST, Load(cancellationToken),
            (USER_UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
        return rows.Select(ToMfaMethod).ToArray();
    }


    public async ValueTask<bool> CreateMfaMethodAsync(CreateMfaMethodCommand command, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var localId = await ScalarAsync<long?>(IdentityMfaQueries.INSERT_METHOD, load,
                    (METHOD_UID, IdentityDatabase.ToBinary(command.MethodId)), (USER_UID, IdentityDatabase.ToBinary(command.UserId)),
                    (KIND, FormatMfaKind(command.Kind)), (LABEL, command.Label), (CREATED_AT, command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (localId is null) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityMfaQueries.INSERT_DATA, load, (METHOD_ID, localId.Value),
                    (SECRET_ENC, command.SecretEncrypted), (PUBLIC_DATA, command.PublicData)).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<bool> CreateMfaEnrollmentAsync(CreateMfaEnrollmentCommand command, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                // An enrollment ticket is intentionally returned only once. Starting again
                // supersedes any abandoned pending ceremony while preserving active factors.
                await ExecAsync(IdentityMfaQueries.CONSUME_PENDING_ENROLLMENTS, load,
                    (USER_UID, IdentityDatabase.ToBinary(command.UserId)),
                    (MODIFIED_AT, command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                await ExecAsync(IdentityMfaQueries.RETIRE_PENDING_METHODS, load,
                    (USER_UID, IdentityDatabase.ToBinary(command.UserId))).ConfigureAwait(false);

                long? replacementId = null;
                if (command.ReplaceMethodId is not null)
                {
                    replacementId = await ScalarAsync<long?>(IdentityMfaQueries.RESOLVE_REPLACEMENT, load,
                        (REPLACE_UID, IdentityDatabase.ToBinary(command.ReplaceMethodId.Value)),
                        (USER_UID, IdentityDatabase.ToBinary(command.UserId))).ConfigureAwait(false);
                    if (replacementId is null)
                    {
                        transaction.Rollback();
                        return false;
                    }
                }

                var localId = await ScalarAsync<long?>(IdentityMfaQueries.INSERT_METHOD, load,
                    (METHOD_UID, IdentityDatabase.ToBinary(command.MethodId)),
                    (USER_UID, IdentityDatabase.ToBinary(command.UserId)),
                    (KIND, "totp"), (LABEL, command.Label),
                    (CREATED_AT, command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (localId is null)
                {
                    transaction.Rollback();
                    return false;
                }

                await ExecAsync(IdentityMfaQueries.INSERT_DATA, load,
                    (METHOD_ID, localId.Value), (SECRET_ENC, command.SecretEncrypted),
                    (PUBLIC_DATA, command.PublicData)).ConfigureAwait(false);
                if (await ExecAsync(IdentityMfaQueries.INSERT_ENROLLMENT, load,
                    (METHOD_ID, localId.Value), (TOKEN_HASH, command.TicketHash),
                    (APPLICATION_UID, command.ApplicationId is null ? null : IdentityDatabase.ToBinary(command.ApplicationId.Value)),
                    (RETURN_URI, command.ReturnUri),
                    (ID, replacementId), (MAX_ATTEMPTS, command.MaximumAttempts),
                    (EXPIRES_AT, command.ExpiresAt.UtcDateTime)).ConfigureAwait(false) != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                foreach (var extension in _extensions)
                    await extension.AfterMfaEnrollmentCreatedAsync(localId.Value, command, load).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<StoredMfaMethod?> FindMfaMethodAsync(Guid methodId, CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityMfaQueries.FIND_METHOD, Load(cancellationToken),
            (METHOD_UID, IdentityDatabase.ToBinary(methodId))).ConfigureAwait(false);
        return row is null ? null : new(ToMfaMethod(row),
            HasValue(row, "secret_enc") ? Required<byte[]>(row, "secret_enc") : null,
            OptionalString(row, "public_data"));
    }


    public async ValueTask<StoredMfaEnrollment?> FindMfaEnrollmentAsync(byte[] ticketHash, CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityMfaQueries.FIND_ENROLLMENT, Load(cancellationToken),
            (TOKEN_HASH, ticketHash)).ConfigureAwait(false);
        if (row is null) return null;
        var method = new StoredMfaMethod(
            ToMfaMethod(row), Required<byte[]>(row, "secret_enc"), OptionalString(row, "public_data"));
        return new(
            method,
            Required<int>(row, "attempts"),
            Required<int>(row, "max_attempts"),
            AsUtc(Required<DateTime>(row, "expires_at")),
            OptionalUtc(row, "consumed_at"),
            OptionalString(row, "return_uri"),
            OptionalGuid(row, "replace_uid"));
    }


    public async ValueTask<bool> FailMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecAsync(IdentityMfaQueries.FAIL_ENROLLMENT, Load(cancellationToken),
            (TOKEN_HASH, ticketHash), (MODIFIED_AT, now.UtcDateTime)).ConfigureAwait(false) == 1;


    public async ValueTask<bool> CompleteMfaEnrollmentAsync(byte[] ticketHash, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityMfaQueries.LOCK_ENROLLMENT, load,
                    (TOKEN_HASH, ticketHash)).ConfigureAwait(false);
                if (row is null || HasValue(row, "consumed_at") ||
                    Required<int>(row, "attempts") >= Required<int>(row, "max_attempts") ||
                    AsUtc(Required<DateTime>(row, "expires_at")) <= now)
                {
                    transaction.Rollback();
                    return false;
                }

                var methodId = Required<long>(row, "method_id");
                if (await ExecAsync(IdentityMfaQueries.ACTIVATE_METHOD_BY_ID, load,
                    (METHOD_ID, methodId), (MODIFIED_AT, now.UtcDateTime)).ConfigureAwait(false) != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                if (HasValue(row, "replace_id"))
                {
                    await ExecAsync(IdentityMfaQueries.RETIRE_METHOD_BY_ID, load,
                        (METHOD_ID, Required<long>(row, "replace_id"))).ConfigureAwait(false);
                }

                if (await ExecAsync(IdentityMfaQueries.CONSUME_ENROLLMENT, load,
                    (TOKEN_HASH, ticketHash), (MODIFIED_AT, now.UtcDateTime)).ConfigureAwait(false) != 1)
                {
                    transaction.Rollback();
                    return false;
                }

                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> RetireMfaMethodAsync(Guid userId, Guid methodId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var changed = await ExecAsync(IdentityMfaQueries.RETIRE_METHOD, load,
                    (USER_UID, IdentityDatabase.ToBinary(userId)),
                    (METHOD_UID, IdentityDatabase.ToBinary(methodId))).ConfigureAwait(false);
                if (changed != 1)
                {
                    transaction.Rollback();
                    return false;
                }
                await ExecAsync(IdentityMfaQueries.CONSUME_METHOD_ENROLLMENT, load,
                    (USER_UID, IdentityDatabase.ToBinary(userId)),
                    (METHOD_UID, IdentityDatabase.ToBinary(methodId)),
                    (MODIFIED_AT, now.UtcDateTime)).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<bool> ConfirmMfaMethodAsync(Guid methodId, DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecAsync(IdentityMfaQueries.CONFIRM_METHOD, Load(cancellationToken),
            (MODIFIED_AT, now.UtcDateTime), (METHOD_UID, IdentityDatabase.ToBinary(methodId))).ConfigureAwait(false) == 1;


    public async ValueTask<bool> TouchMfaMethodAsync(Guid methodId, DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecAsync(IdentityMfaQueries.TOUCH_METHOD, Load(cancellationToken),
            (MODIFIED_AT, now.UtcDateTime), (METHOD_UID, IdentityDatabase.ToBinary(methodId))).ConfigureAwait(false) == 1;


    public async ValueTask<bool> ReplaceRecoveryCodesAsync(Guid userId, IReadOnlyCollection<byte[]> codeHashes, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var localUserId = await ScalarAsync<long?>(IdentityMfaQueries.RESOLVE_USER, load,
                    (USER_UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
                if (localUserId is null) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityMfaQueries.DELETE_RECOVERY, load, (USER_ID, localUserId.Value)).ConfigureAwait(false);
                foreach (var hash in codeHashes)
                    await ExecAsync(IdentityMfaQueries.INSERT_RECOVERY, load,
                        (USER_ID, localUserId.Value), (CODE_HASH, hash), (CREATED_AT, now.UtcDateTime)).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<bool> ConsumeRecoveryCodeAsync(Guid userId, byte[] codeHash, DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecAsync(IdentityMfaQueries.CONSUME_RECOVERY, Load(cancellationToken),
            (MODIFIED_AT, now.UtcDateTime), (USER_UID, IdentityDatabase.ToBinary(userId)), (CODE_HASH, codeHash)).ConfigureAwait(false) == 1;


    private static MfaMethodInfo ToMfaMethod(Haley.Models.DbRow row) => new(
        ToGuid(row, "method_uid"), ToGuid(row, "user_uid"), ParseMfaKind(Required<string>(row, "kind")),
        OptionalString(row, "label"), (IdentityRecordStatus)Required<int>(row, "status"), AsUtc(Required<DateTime>(row, "created_at")),
        OptionalUtc(row, "verified_at"), OptionalUtc(row, "last_used_at"));

    private static string FormatMfaKind(MfaKind kind) => kind switch { MfaKind.EmailOtp => "email_otp", MfaKind.Saml => "saml", MfaKind.Totp => "totp", MfaKind.RecoveryCode => "recovery", _ => throw new ArgumentOutOfRangeException(nameof(kind)) };

    private static MfaKind ParseMfaKind(string kind) => kind switch { "email_otp" => MfaKind.EmailOtp, "saml" => MfaKind.Saml, "totp" => MfaKind.Totp, "recovery" => MfaKind.RecoveryCode, _ => throw new InvalidDataException($"Unknown MFA kind '{kind}'.") };

    public async ValueTask<UserIdentity?> FindUserByVerifiedEmailAsync(
        string emailNormalized,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityLifecycleQueries.FIND_VERIFIED_EMAIL, Load(cancellationToken),
            (EMAIL, emailNormalized)).ConfigureAwait(false);
        return row is null ? null : ToUser(row);
    }


    public async ValueTask<IReadOnlyCollection<string>> ListVerifiedEmailDomainsAsync(
        Guid userId,
        CancellationToken cancellationToken)
    {
        var rows = await RowsAsync(IdentityLifecycleQueries.LIST_VERIFIED_EMAILS, Load(cancellationToken),
            (USER_UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
        return rows.Select(row => Required<string>(row, "normalized")).ToArray();
    }


    public async ValueTask<UserIdentity?> FindPendingUserByEmailAsync(
        string emailNormalized,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityLifecycleQueries.FIND_PENDING_EMAIL, Load(cancellationToken),
            (EMAIL, emailNormalized)).ConfigureAwait(false);
        return row is null ? null : ToUser(row);
    }


    public async ValueTask<UserIdentity?> FindUserByOriginAsync(
        Guid clientId,
        string origin,
        byte[] sourceHash,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityLifecycleQueries.FIND_USER_BY_ORIGIN, Load(cancellationToken),
            (APPLICATION_UID, IdentityDatabase.ToBinary(clientId)), (ORIGIN, origin), (SOURCE_HASH, sourceHash)).ConfigureAwait(false);
        return row is null ? null : ToUser(row);
    }


    public async ValueTask<bool> CreateMailboxUserAsync(
        CreateMailboxUserCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var localUserId = await ScalarAsync<long?>(IdentityLifecycleQueries.INSERT_MAILBOX_USER, load,
                    (UID, IdentityDatabase.ToBinary(command.UserId)), (STATUS, (int?)(FormatStatus(command.Status))),
                    (USERNAME, command.EmailNormalized), (DISPLAY_NAME, command.DisplayName),
                    (FLAGS, command.Flags), (CREATED_AT, command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (localUserId is null) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityLifecycleQueries.INSERT_EMAIL_CONTACT, load,
                    (CONTACT_UID, IdentityDatabase.ToBinary(command.ContactId)), (USER_ID, localUserId.Value),
                    (EMAIL, command.EmailNormalized), (DISPLAY_NAME, command.EmailDisplay),
                    (CREATED_AT, command.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (!await InsertOriginAsync(load, command).ConfigureAwait(false))
                { transaction.Rollback(); return false; }
                await AddOutboxAsync(load, _settings.EventPrefix + ".user.invited.v2", "user_account", command.UserId,
                    JsonSerializer.Serialize(new { userId = command.UserId, status = FormatStatus(command.Status) }), command.CreatedAt)
                    .ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<bool> CreateMailboxInvitationAsync(
        CreateMailboxUserCommand user,
        CreateVerificationChallengeCommand challenge,
        CancellationToken cancellationToken)
    {
        if (challenge.SubjectId != user.UserId) return false;
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var policyId = await ScalarAsync<long?>(IdentityLifecycleQueries.FIND_POLICY_ID, load,
                    (POLICY_CODE, challenge.PolicyCode)).ConfigureAwait(false);
                if (policyId is null) { transaction.Rollback(); return false; }
                var localUserId = await ScalarAsync<long?>(IdentityLifecycleQueries.INSERT_MAILBOX_USER, load,
                    (UID, IdentityDatabase.ToBinary(user.UserId)), (STATUS, (int?)(FormatStatus(user.Status))),
                    (USERNAME, user.EmailNormalized), (DISPLAY_NAME, user.DisplayName),
                    (FLAGS, user.Flags), (CREATED_AT, user.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (localUserId is null) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityLifecycleQueries.INSERT_EMAIL_CONTACT, load,
                    (CONTACT_UID, IdentityDatabase.ToBinary(user.ContactId)), (USER_ID, localUserId.Value),
                    (EMAIL, user.EmailNormalized), (DISPLAY_NAME, user.EmailDisplay),
                    (CREATED_AT, user.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (!await InsertOriginAsync(load, user).ConfigureAwait(false))
                { transaction.Rollback(); return false; }
                var challengeId = await ScalarAsync<long?>(IdentityLifecycleQueries.INSERT_CHALLENGE, load,
                    (UID, IdentityDatabase.ToBinary(challenge.ChallengeId)), (OWNER_TENANT_UID, DbBinary(challenge.TenantId)),
                    (APPLICATION_UID, IdentityDatabase.ToBinary(challenge.ApplicationId)), (ID, policyId.Value),
                    (REASON, challenge.Purpose), (USER_UID, IdentityDatabase.ToBinary(challenge.SubjectId)),
                    (DESTINATION_HASH, challenge.DestinationHash), (CONTEXT_HASH, challenge.ContextHash),
                    (CREATED_AT, challenge.CreatedAt.UtcDateTime), (NOT_BEFORE, challenge.NotBefore.UtcDateTime),
                    (EXPIRES_AT, challenge.ExpiresAt.UtcDateTime)).ConfigureAwait(false);
                if (challengeId is null) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityLifecycleQueries.INSERT_CHALLENGE_CTX, load,
                    (CHALLENGE_ID, challengeId.Value),
                    (OWNER_TENANT_UID, DbBinary(challenge.TenantId)),
                    (APPLICATION_UID, IdentityDatabase.ToBinary(challenge.ApplicationId)),
                    (REASON, challenge.Purpose),
                    (USER_UID, IdentityDatabase.ToBinary(challenge.SubjectId)),
                    (DESTINATION_HASH, challenge.DestinationHash),
                    (CONTEXT_HASH, challenge.ContextHash)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.INSERT_CHALLENGE_DATA, load,
                    (CHALLENGE_ID, challengeId.Value), (CODE_HASH, challenge.CodeHash),
                    (CODE_ALGORITHM, challenge.CodeAlgorithm), (CODE_PARAMS, challenge.CodeParameters),
                    (CODE_EXPIRES_AT, challenge.CodeExpiresAt.UtcDateTime),
                    (LINK_HASH, challenge.LinkHash)).ConfigureAwait(false);
                await AddOutboxAsync(load, _settings.EventPrefix + ".user.invited.v2", "user_account", user.UserId,
                    JsonSerializer.Serialize(new { userId = user.UserId, status = FormatStatus(user.Status) }), user.CreatedAt)
                    .ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<bool> CreateBootstrapUserAsync(
        CreateLocalUserCommand user,
        IdentityOriginCommand origin,
        CancellationToken cancellationToken)
    {
        if (origin.UserId != user.UserId || origin.ApplicationId == Guid.Empty || origin.SourceHash.Length != 32)
            return false;
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var localUserId = await ScalarAsync<long?>(IdentityUserQueries.INSERT_USER, load,
                    (UID, IdentityDatabase.ToBinary(user.UserId)), (STATUS, (int?)(FormatStatus(user.Status))),
                    (USERNAME, user.UsernameNormalized), (DISPLAY_NAME, user.DisplayName),
                    (FLAGS, user.RequirePasswordChange ? 3 : 1),
                    (CREATED_AT, user.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (localUserId is null) { transaction.Rollback(); return false; }
                if (await ExecAsync(IdentityLifecycleQueries.INSERT_USER_ORIGIN, load,
                        (USER_UID, IdentityDatabase.ToBinary(origin.UserId)),
                        (APPLICATION_UID, IdentityDatabase.ToBinary(origin.ApplicationId)), (ORIGIN, origin.Origin),
                        (SOURCE_HASH, origin.SourceHash), (CREATED_AT, origin.CreatedAt.UtcDateTime)).ConfigureAwait(false) != 1)
                { transaction.Rollback(); return false; }
                await ExecAsync(IdentityUserQueries.INSERT_CREDENTIAL, load,
                    (CREDENTIAL_UID, IdentityDatabase.ToBinary(user.CredentialId)), (USER_ID, localUserId.Value),
                    (SECRET_HASH, user.SecretHash), (ALGORITHM, user.Algorithm),
                    (PARAMS, user.ParametersPayload), (CREATED_AT, user.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                if (user.EmailContactId is { } emailContactId)
                {
                    await ExecAsync(IdentityLifecycleQueries.INSERT_EMAIL_CONTACT, load,
                        (CONTACT_UID, IdentityDatabase.ToBinary(emailContactId)),
                        (USER_ID, localUserId.Value), (EMAIL, user.UsernameNormalized),
                        (DISPLAY_NAME, user.UsernameNormalized),
                        (CREATED_AT, user.CreatedAt.UtcDateTime)).ConfigureAwait(false);
                }
                await AddOutboxAsync(load, _settings.EventPrefix + ".user.created.v2", "user_account", user.UserId,
                    JsonSerializer.Serialize(new { userId = user.UserId, status = FormatStatus(user.Status), origin = origin.Origin }), user.CreatedAt)
                    .ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<bool> CreateVerificationChallengeAsync(
        CreateVerificationChallengeCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var policyId = await ScalarAsync<long?>(IdentityLifecycleQueries.FIND_POLICY_ID, load,
                    (POLICY_CODE, command.PolicyCode)).ConfigureAwait(false);
                if (policyId is null) { transaction.Rollback(); return false; }
                var throttled = await ScalarAsync<long>(IdentityLifecycleQueries.CHALLENGE_THROTTLED, load,
                    (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId)), (REASON, command.Purpose),
                    (USER_UID, IdentityDatabase.ToBinary(command.SubjectId)), (CREATED_AT, command.CreatedAt.UtcDateTime),
                    (COOLDOWN_SEC, command.ExhaustedCooldownSeconds)).ConfigureAwait(false);
                if (throttled > 0) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityLifecycleQueries.CANCEL_PENDING_CHALLENGES, load,
                    (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId)), (REASON, command.Purpose),
                    (USER_UID, IdentityDatabase.ToBinary(command.SubjectId)), (CREATED_AT, command.CreatedAt.UtcDateTime))
                    .ConfigureAwait(false);
                var localId = await ScalarAsync<long?>(IdentityLifecycleQueries.INSERT_CHALLENGE, load,
                    (UID, IdentityDatabase.ToBinary(command.ChallengeId)), (OWNER_TENANT_UID, DbBinary(command.TenantId)),
                    (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId)), (ID, policyId.Value),
                    (REASON, command.Purpose), (USER_UID, IdentityDatabase.ToBinary(command.SubjectId)),
                    (DESTINATION_HASH, command.DestinationHash), (CONTEXT_HASH, command.ContextHash),
                    (CREATED_AT, command.CreatedAt.UtcDateTime), (NOT_BEFORE, command.NotBefore.UtcDateTime),
                    (EXPIRES_AT, command.ExpiresAt.UtcDateTime)).ConfigureAwait(false);
                if (localId is null) { transaction.Rollback(); return false; }
                await ExecAsync(IdentityLifecycleQueries.INSERT_CHALLENGE_CTX, load,
                    (CHALLENGE_ID, localId.Value),
                    (OWNER_TENANT_UID, DbBinary(command.TenantId)),
                    (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId)),
                    (REASON, command.Purpose),
                    (USER_UID, IdentityDatabase.ToBinary(command.SubjectId)),
                    (DESTINATION_HASH, command.DestinationHash),
                    (CONTEXT_HASH, command.ContextHash)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.INSERT_CHALLENGE_DATA, load,
                    (CHALLENGE_ID, localId.Value), (CODE_HASH, command.CodeHash),
                    (CODE_ALGORITHM, command.CodeAlgorithm), (CODE_PARAMS, command.CodeParameters),
                    (CODE_EXPIRES_AT, command.CodeExpiresAt.UtcDateTime),
                    (LINK_HASH, command.LinkHash)).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<StoredVerificationChallenge?> FindVerificationChallengeAsync(
        Guid challengeId,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityLifecycleQueries.FIND_CHALLENGE, Load(cancellationToken),
            (UID, IdentityDatabase.ToBinary(challengeId))).ConfigureAwait(false);
        return row is null ? null : new StoredVerificationChallenge(
            Required<long>(row, "local_challenge_id"), ToGuid(row, "challenge_uid"), ToGuid(row, "application_uid"),
            OptionalGuid(row, "subject_uid"), Required<string>(row, "purpose"), Required<byte[]>(row, "context_hash"),
            (IdentityRecordStatus)Required<int>(row, "status"), Required<int>(row, "attempts"), Required<int>(row, "max_attempts"),
            Required<int>(row, "grant_validity"), Required<byte[]>(row, "code_hash"),
            Required<string>(row, "code_algorithm"), OptionalString(row, "code_params"),
            AsUtc(Required<DateTime>(row, "code_expires_at")),
            HasValue(row, "link_hash") ? Required<byte[]>(row, "link_hash") : null,
            AsUtc(Required<DateTime>(row, "not_before")), AsUtc(Required<DateTime>(row, "expires_at")));
    }


    public async ValueTask<bool> CompleteVerificationAsync(
        CompleteVerificationCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var locked = await RowAsync(IdentityLifecycleQueries.LOCK_CHALLENGE, load,
                    (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);
                if (locked is null || !((IdentityRecordStatus)Required<int>(locked, "status") == IdentityRecordStatus.Pending) ||
                    Required<int>(locked, "attempts") != command.ExpectedAttempts ||
                    Required<int>(locked, "attempts") >= Required<int>(locked, "max_attempts") ||
                    AsUtc(Required<DateTime>(locked, "not_before")) > command.OccurredAt ||
                    AsUtc(Required<DateTime>(locked, "expires_at")) <= command.OccurredAt)
                { transaction.Rollback(); return false; }
                var exhausted = !command.Succeeded &&
                    Required<int>(locked, "attempts") + 1 >= Required<int>(locked, "max_attempts");
                var outcome = command.Succeeded ? "success" : exhausted ? "exhausted" : "incorrect";
                await ExecAsync(IdentityLifecycleQueries.INSERT_CHALLENGE_ATTEMPT, load,
                    (CHALLENGE_ID, command.LocalChallengeId), (OUTCOME, outcome), (IP_HASH, command.IpHash),
                    (USER_AGENT_HASH, command.UserAgentHash), (OCCURRED_AT, command.OccurredAt.UtcDateTime)).ConfigureAwait(false);
                if (!command.Succeeded)
                {
                    await ExecAsync(IdentityLifecycleQueries.FAIL_CHALLENGE, load,
                        (EXHAUSTED, exhausted ? 1 : 0), (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);
                    transaction.Commit();
                    return false;
                }
                await ExecAsync(IdentityLifecycleQueries.VERIFY_CHALLENGE, load,
                    (OCCURRED_AT, command.OccurredAt.UtcDateTime), (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.INSERT_GRANT, load,
                    (GRANT_UID, IdentityDatabase.ToBinary(command.GrantId)), (OCCURRED_AT, command.OccurredAt.UtcDateTime),
                    (GRANT_EXPIRES_AT, command.GrantExpiresAt.UtcDateTime), (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.INSERT_GRANT_CTX, load,
                    (GRANT_UID, IdentityDatabase.ToBinary(command.GrantId))).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<bool> ConsumeEnrollmentGrantAsync(
        EnrollPasswordCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                foreach (var extension in _extensions)
                    if (!await extension.IsApplicationActiveAsync(command.ApplicationId, load).ConfigureAwait(false))
                    { transaction.Rollback(); return false; }
                var grant = await RowAsync(IdentityLifecycleQueries.LOCK_ENROLLMENT_GRANT, load,
                    (GRANT_UID, IdentityDatabase.ToBinary(command.GrantId)),
                    (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId)),
                    (USER_UID, IdentityDatabase.ToBinary(command.UserId))).ConfigureAwait(false);
                if (grant is null || HasValue(grant, "consumed_at") ||
                    AsUtc(Required<DateTime>(grant, "expires_at")) <= command.EnrolledAt ||
                    !string.Equals(Required<string>(grant, "purpose"), IdentityPurposes.Enrollment, StringComparison.Ordinal) ||
                    !((IdentityRecordStatus)Required<int>(grant, "client_status") == IdentityRecordStatus.Active) ||
                    (IdentityRecordStatus)Required<int>(grant, "status") is not (IdentityRecordStatus.Pending or IdentityRecordStatus.Active) ||
                    !Required<byte[]>(grant, "context_hash").SequenceEqual(command.ContextHash))
                { transaction.Rollback(); return false; }
                var userId = Required<long>(grant, "local_user_id");
                var challengeId = Required<long>(grant, "local_challenge_id");
                await ExecAsync(IdentityLifecycleQueries.RETIRE_CURRENT_PASSWORDS, load,
                    (OCCURRED_AT, command.EnrolledAt.UtcDateTime), (USER_ID, userId)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.INSERT_ENROLLED_PASSWORD, load,
                    (CREDENTIAL_UID, IdentityDatabase.ToBinary(command.CredentialId)), (USER_ID, userId),
                    (SECRET_HASH, command.SecretHash), (ALGORITHM, command.Algorithm),
                    (PARAMS, command.ParametersPayload), (OCCURRED_AT, command.EnrolledAt.UtcDateTime)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.ACTIVATE_ENROLLED_USER, load,
                    (OCCURRED_AT, command.EnrolledAt.UtcDateTime), (USER_ID, userId)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.VERIFY_USER_EMAIL, load,
                    (OCCURRED_AT, command.EnrolledAt.UtcDateTime), (USER_ID, userId)).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.CONSUME_GRANT, load,
                    (OCCURRED_AT, command.EnrolledAt.UtcDateTime), (USER_UID, IdentityDatabase.ToBinary(command.UserId)),
                    (ID, Required<long>(grant, "local_grant_id"))).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.CONSUME_CHALLENGE, load,
                    (OCCURRED_AT, command.EnrolledAt.UtcDateTime), (CHALLENGE_ID, challengeId)).ConfigureAwait(false);
                await AddOutboxAsync(load, _settings.EventPrefix + ".enrollment.completed.v1", "user_account", command.UserId,
                    JsonSerializer.Serialize(new { userId = command.UserId }), command.EnrolledAt).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }


    public async ValueTask<StoredPasswordResetSubject?> FindPasswordResetSubjectAsync(
        string channel,
        string destinationNormalized,
        CancellationToken cancellationToken)
    {
        var kind = string.Equals(channel, "sms", StringComparison.Ordinal) ? "mobile" : channel;
        var row = await RowAsync(IdentityLifecycleQueries.FIND_PASSWORD_RESET_SUBJECT, Load(cancellationToken),
            (KIND, kind), (DESTINATION, destinationNormalized)).ConfigureAwait(false);
        return row is null
            ? null
            : new StoredPasswordResetSubject(
                ToGuid(row, "user_uid"),
                ParseStatus(Required<int>(row, "status")),
                channel,
                Required<string>(row, "destination_normalized"),
                Required<string>(row, "destination_display"));
    }


    public async ValueTask<StoredPasswordlessSubject?> FindPasswordlessSubjectAsync(
        string emailNormalized,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(
            IdentityLifecycleQueries.FIND_PASSWORDLESS_SUBJECT_BY_EMAIL,
            Load(cancellationToken),
            (DESTINATION, emailNormalized)).ConfigureAwait(false);
        return ToPasswordlessSubject(row);
    }


    public async ValueTask<StoredPasswordlessSubject?> FindPasswordlessSubjectAsync(
        Guid userId,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(
            IdentityLifecycleQueries.FIND_PASSWORDLESS_SUBJECT_BY_USER,
            Load(cancellationToken),
            (USER_UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
        return ToPasswordlessSubject(row);
    }


    private static StoredPasswordlessSubject? ToPasswordlessSubject(DbRow? row) => row is null
        ? null
        : new(
            Required<long>(row, "local_user_id"),
            ToUser(row),
            Required<string>(row, "destination_normalized"),
            Required<string>(row, "destination_display"));


    public async ValueTask<bool> ConsumePasswordResetGrantAsync(
        CompletePasswordResetCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                foreach (var extension in _extensions)
                    if (!await extension.IsApplicationActiveAsync(command.ApplicationId, load).ConfigureAwait(false))
                    { transaction.Rollback(); return false; }
                var grant = await RowAsync(IdentityLifecycleQueries.LOCK_PASSWORD_RESET_GRANT, load,
                    (GRANT_UID, IdentityDatabase.ToBinary(command.GrantId)),
                    (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId))).ConfigureAwait(false);
                if (grant is null || HasValue(grant, "consumed_at") ||
                    AsUtc(Required<DateTime>(grant, "expires_at")) <= command.CompletedAt ||
                    !string.Equals(Required<string>(grant, "purpose"), IdentityPurposes.PasswordReset, StringComparison.Ordinal) ||
                    !((IdentityRecordStatus)Required<int>(grant, "client_status") == IdentityRecordStatus.Active) ||
                    !((IdentityRecordStatus)Required<int>(grant, "status") == IdentityRecordStatus.Active) ||
                    ToGuid(grant, "credential_uid") != command.CurrentCredentialId ||
                    !Required<byte[]>(grant, "context_hash").SequenceEqual(command.ContextHash))
                {
                    transaction.Rollback();
                    return false;
                }

                var userId = Required<long>(grant, "local_user_id");
                var localCredentialId = Required<long>(grant, "local_credential_id");
                var publicUserId = ToGuid(grant, "user_uid");
                var changed = await ReplacePasswordAsync(
                    load,
                    grant,
                    userId,
                    localCredentialId,
                    publicUserId,
                    command.CredentialId,
                    command.SecretHash,
                    command.Algorithm,
                    command.ParametersPayload,
                    requirePasswordChange: false,
                    command.CompletedAt,
                    _settings.EventPrefix + ".password.recovered.v1",
                    JsonSerializer.Serialize(new { userId = publicUserId, clientId = command.ApplicationId })).ConfigureAwait(false);
                if (!changed)
                {
                    transaction.Rollback();
                    return false;
                }

                await ExecAsync(IdentityLifecycleQueries.CONSUME_GRANT, load,
                    (OCCURRED_AT, command.CompletedAt.UtcDateTime),
                    (USER_UID, IdentityDatabase.ToBinary(publicUserId)),
                    (ID, Required<long>(grant, "local_grant_id"))).ConfigureAwait(false);
                await ExecAsync(IdentityLifecycleQueries.CONSUME_CHALLENGE, load,
                    (OCCURRED_AT, command.CompletedAt.UtcDateTime),
                    (CHALLENGE_ID, Required<long>(grant, "local_challenge_id"))).ConfigureAwait(false);
                transaction.Commit();
                return true;
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }


    public async ValueTask<StoredPasswordResetCredential?> FindPasswordResetGrantCredentialAsync(
        Guid grantId,
        Guid clientId,
        DateTimeOffset evaluatedAt,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityLifecycleQueries.FIND_PASSWORD_RESET_GRANT_CREDENTIAL, Load(cancellationToken),
            (GRANT_UID, IdentityDatabase.ToBinary(grantId)),
            (APPLICATION_UID, IdentityDatabase.ToBinary(clientId)),
            (OCCURRED_AT, evaluatedAt.UtcDateTime)).ConfigureAwait(false);
        return row is null
            ? null
            : new StoredPasswordResetCredential(
                ToGuid(row, "credential_uid"),
                Required<byte[]>(row, "secret_hash"),
                Required<string>(row, "algorithm"),
                OptionalString(row, "params"));
    }


    private async ValueTask<bool> InsertOriginAsync(
        Haley.Models.DbExecutionLoad load,
        CreateMailboxUserCommand user)
    {
        if (user.OriginClientId is null && user.Origin is null && user.SourceHash is null) return true;
        if (user.OriginClientId is null || user.OriginClientId == Guid.Empty ||
            string.IsNullOrWhiteSpace(user.Origin) || user.SourceHash is not { Length: 32 }) return false;
        return await ExecAsync(IdentityLifecycleQueries.INSERT_USER_ORIGIN, load,
            (USER_UID, IdentityDatabase.ToBinary(user.UserId)),
            (APPLICATION_UID, IdentityDatabase.ToBinary(user.OriginClientId.Value)), (ORIGIN, user.Origin),
            (SOURCE_HASH, user.SourceHash), (CREATED_AT, user.CreatedAt.UtcDateTime)).ConfigureAwait(false) == 1;
    }

}
