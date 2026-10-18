using Haley.Internal;
using Haley.DAL;
using static Haley.Internal.IdentityFields;

namespace Haley.Services;

public sealed partial class IdentityStore
{
    public async ValueTask<int> PruneUnusedMfaMethodsAsync(Guid userId, CancellationToken cancellationToken)
    {
        // One atomic DELETE rechecks eligibility while acquiring row locks. Its
        // cascades remove secret data, enrollment tickets and host enrollment context.
        return await ExecAsync(IdentityMfaQueries.PRUNE_UNUSED_METHODS, Load(cancellationToken),
            (USER_UID, IdentityDatabase.ToBinary(userId))).ConfigureAwait(false);
    }
}
