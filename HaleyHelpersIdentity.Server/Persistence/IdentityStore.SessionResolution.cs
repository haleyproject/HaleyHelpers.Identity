using System.Text.Json;
using Haley.Internal;
using Haley.DAL;

namespace Haley.Services;

public sealed partial class IdentityStore
{
    public async ValueTask<ResolvedIdentitySession?> ResolveOpaqueSessionAsync(Guid applicationId, byte[] tokenHash,
        DateTimeOffset at, CancellationToken cancellationToken, string? ownerContext = null)
    {
        var load = Load(cancellationToken);
        var row = await RowAsync(IdentityAccountQueries.ResolveSession, load,
            ("@application", IdentityDatabase.ToBinary(applicationId)), ("@hash", tokenHash), ("@at", at.UtcDateTime)).ConfigureAwait(false);
        if (row is null) return null;
        var sessionId = ToGuid(row, "session_uid");
        foreach (var extension in _extensions)
            if (!await extension.CanUseOpaqueSessionAsync(sessionId, ownerContext, load).ConfigureAwait(false)) return null;
        var methods = JsonSerializer.Deserialize<string[]>(Required<string>(row, "auth_methods")) ?? [];
        return new(sessionId, AsUtc(Required<DateTime>(row, "expires_at")), ToGuid(row, "user_uid"),
            Required<string>(row, "display_name"), HasValue(row, "email") ? Required<string>(row, "email") : null,
            HasValue(row, "verified_at"), ParseStatus(Required<int>(row, "status")), methods);
    }
}
