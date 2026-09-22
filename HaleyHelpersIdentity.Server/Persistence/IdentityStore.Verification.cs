using Haley.Internal;
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
                    transaction.Rollback();
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
                    transaction.Commit();
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

}
