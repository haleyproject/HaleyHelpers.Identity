using Haley.Internal;
using Haley.DAL;
using static Haley.Internal.IdentityFields;
namespace Haley.Services;

public sealed partial class IdentityStore
{
    public async ValueTask<bool> CompletePasswordlessVerificationAsync(
        CompletePasswordlessVerificationCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var completed = await CompletePasswordlessVerificationAsync(command, load).ConfigureAwait(false);
                transaction.Commit();
                return completed;
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    private async ValueTask<bool> CompletePasswordlessVerificationAsync(CompletePasswordlessVerificationCommand command, DbExecutionLoad load)
    {
        var locked = await RowAsync(
            IdentityLifecycleQueries.LOCK_CHALLENGE,
            load,
            (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);
        if (locked is null ||
            !((IdentityRecordStatus)Required<int>(locked, "status") == IdentityRecordStatus.Pending) ||
            Required<int>(locked, "attempts") != command.ExpectedAttempts ||
            Required<int>(locked, "attempts") >= Required<int>(locked, "max_attempts") ||
            AsUtc(Required<DateTime>(locked, "not_before")) > command.OccurredAt ||
            AsUtc(Required<DateTime>(locked, "expires_at")) <= command.OccurredAt)
        {

            return false;
        }

        var exhausted = !command.Succeeded &&
            Required<int>(locked, "attempts") + 1 >= Required<int>(locked, "max_attempts");
        var outcome = command.Succeeded ? "success" : exhausted ? "exhausted" : "incorrect";
        await ExecAsync(
            IdentityLifecycleQueries.INSERT_CHALLENGE_ATTEMPT,
            load,
            (CHALLENGE_ID, command.LocalChallengeId),
            (OUTCOME, outcome),
            (IP_HASH, command.IpHash),
            (USER_AGENT_HASH, command.UserAgentHash),
            (OCCURRED_AT, command.OccurredAt.UtcDateTime)).ConfigureAwait(false);
        if (!command.Succeeded)
        {
            await ExecAsync(
                IdentityLifecycleQueries.FAIL_CHALLENGE,
                load,
                (EXHAUSTED, exhausted ? 1 : 0),
                (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);

            return false;
        }

        await ExecAsync(
            IdentityLifecycleQueries.VERIFY_CHALLENGE,
            load,
            (OCCURRED_AT, command.OccurredAt.UtcDateTime),
            (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);
        await ExecAsync(
            IdentityLifecycleQueries.CONSUME_CHALLENGE,
            load,
            (OCCURRED_AT, command.OccurredAt.UtcDateTime),
            (CHALLENGE_ID, command.LocalChallengeId)).ConfigureAwait(false);

        return true;

    }

    public async ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(string email, CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityVerificationQueries.ByEmail, Load(cancellationToken), ("@email", email)).ConfigureAwait(false);
        return row is null ? null : ToVerificationSubject(row);
    }

    public async ValueTask<StoredVerificationSubject?> FindVerificationSubjectAsync(Guid userId, byte[] destinationHash, CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityVerificationQueries.ByDestination, Load(cancellationToken),
            ("@uid", IdentityDatabase.ToBinary(userId)), ("@destination", destinationHash)).ConfigureAwait(false);
        return row is null ? null : ToVerificationSubject(row);
    }

    private static StoredVerificationSubject ToVerificationSubject(DbRow row) => new(ToUser(row), ToGuid(row, "contact_uid"),
        Required<string>(row, "email"), OptionalUtc(row, "verified_at"), (Required<uint>(row, "contact_flags") & 2) == 2,
        OptionalGuid(row, "credential_uid"));

    public async ValueTask<bool> CompleteIdentityVerificationAsync(CompleteIdentityVerificationCommand command,
        Func<PasswordHash, bool> isReusedPassword, CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                foreach (var extension in _extensions)
                    if (!await extension.IsApplicationActiveAsync(command.Challenge.ApplicationId, load).ConfigureAwait(false))
                    { transaction.Rollback(); return false; }
                var row = await RowAsync(IdentityVerificationQueries.LockSubject, load,
                    ("@uid", IdentityDatabase.ToBinary(command.Subject.Identity.UserId)),
                    ("@contact", IdentityDatabase.ToBinary(command.Subject.ContactId))).ConfigureAwait(false);
                var current = row is null ? null : ToVerificationSubject(row);
                if (current is null || current.Identity.Status != command.Subject.Identity.Status ||
                    current.Identity.PasswordChangeRequired != command.Subject.Identity.PasswordChangeRequired ||
                    current.CredentialId != command.Subject.CredentialId || current.Email != command.Subject.Email ||
                    current.VerifiedAt != command.Subject.VerifiedAt || current.RecoveryEnabled != command.Subject.RecoveryEnabled ||
                    !IdentityVerificationPolicy.IsEligible(current, command.Purpose) ||
                    command.Challenge.SubjectId != current.Identity.UserId ||
                    command.Challenge.Purpose != IdentityVerificationPolicy.PurposeCode(command.Purpose) ||
                    command.Challenge.DestinationHash is null ||
                    !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                        command.Challenge.DestinationHash, VerificationProofService.Hash(current.Email)))
                { transaction.Rollback(); return false; }

                if (!await CompletePasswordlessVerificationAsync(new(command.Challenge.LocalChallengeId, true,
                    command.Challenge.Attempts, null, null, command.CompletedAt), load).ConfigureAwait(false))
                { transaction.Rollback(); return false; }

                if (command.Password is not null)
                {
                    if (command.Purpose is not (VerificationPurpose.Onboarding or VerificationPurpose.PasswordReset) ||
                        command.Password.UserId != current.Identity.UserId ||
                        !await SetCredentialAsync(command.Password, isReusedPassword, load).ConfigureAwait(false))
                    { transaction.Rollback(); return false; }
                }
                else if (command.Purpose == VerificationPurpose.PasswordReset ||
                    command.Purpose == VerificationPurpose.Onboarding && current.Identity.PasswordChangeRequired)
                { transaction.Rollback(); return false; }

                if (command.Purpose is VerificationPurpose.EmailVerification or VerificationPurpose.Onboarding)
                {
                    await ExecAsync(IdentityVerificationQueries.VerifyContact, load, ("@contact", IdentityDatabase.ToBinary(current.ContactId)),
                        ("@at", command.CompletedAt.UtcDateTime)).ConfigureAwait(false);
                    await ExecAsync(IdentityVerificationQueries.ClearContactVerificationPending, load,
                        ("@uid", IdentityDatabase.ToBinary(current.Identity.UserId)), ("@at", command.CompletedAt.UtcDateTime)).ConfigureAwait(false);
                    await AddOutboxAsync(load, _settings.EventPrefix + ".email.verified.v1", "user_account", current.Identity.UserId,
                        System.Text.Json.JsonSerializer.Serialize(new { userId = current.Identity.UserId, contactId = current.ContactId }),
                        command.CompletedAt).ConfigureAwait(false);
                }
                if (command.Purpose == VerificationPurpose.Onboarding)
                {
                    await ExecAsync(IdentityVerificationQueries.ActivateAccount, load, ("@uid", IdentityDatabase.ToBinary(current.Identity.UserId)),
                        ("@at", command.CompletedAt.UtcDateTime)).ConfigureAwait(false);
                    foreach (var extension in _extensions)
                        await extension.AfterAccountStatusChangeAsync(current.Identity.UserId, Required<long>(row!, "local_user_id"),
                            IdentityStatus.Active, "onboarding_verified", command.CompletedAt, load).ConfigureAwait(false);
                    await AddOutboxAsync(load, _settings.EventPrefix + ".enrollment.completed.v1", "user_account", current.Identity.UserId,
                        System.Text.Json.JsonSerializer.Serialize(new { userId = current.Identity.UserId }), command.CompletedAt).ConfigureAwait(false);
                }
                if (command.Purpose == VerificationPurpose.PasswordlessLogin)
                {
                    if (command.Session is null || command.Session.AuthenticatedUserId != current.Identity.UserId ||
                        command.Session.Account.ApplicationId != command.Challenge.ApplicationId ||
                        !await StartOpaqueSessionAsync(command.Session, load).ConfigureAwait(false))
                    { transaction.Rollback(); return false; }
                }
                else if (command.Session is not null) { transaction.Rollback(); return false; }
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }
}
