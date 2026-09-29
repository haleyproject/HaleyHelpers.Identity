using Haley.DAL;
using Haley.Internal;

namespace Haley.Services;

public sealed partial class IdentityStore
{
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
