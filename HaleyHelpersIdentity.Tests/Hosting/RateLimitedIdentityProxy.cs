using System.Reflection;
using Haley.Abstractions;
using Haley.Models;

namespace Haley.Tests;

public class RateLimitedIdentityProxy : DispatchProxy
{
    public Dictionary<string, Guid> Accounts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Guid> Sessions { get; } = new();
    public int AccountLookups { get; private set; }
    public int SessionResolutions { get; private set; }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        switch (targetMethod?.Name)
        {
            case nameof(IIdentity.GetAccountAsync):
                return ValueTask.FromResult<IFeedback<UserIdentity>>(new Feedback<UserIdentity>(true, "Found.", Account((Guid)args![0]!)));
            case nameof(IIdentity.FindAccountAsync):
                AccountLookups++;
                return ValueTask.FromResult<IFeedback<UserIdentity>>(Accounts.TryGetValue(((string)args![0]!).Trim(), out var account)
                    ? new Feedback<UserIdentity>(true, "Found.", Account(account))
                    : new Feedback<UserIdentity>(false, "Not found.") { Key = "account_not_found" });
            case nameof(IIdentity.ResolveSessionAsync):
                SessionResolutions++;
                return ValueTask.FromResult<IFeedback<ResolvedIdentitySession>>(Sessions.TryGetValue((string)args![0]!, out var user)
                    ? new Feedback<ResolvedIdentitySession>(true, "Valid.", new(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(10),
                        user, "Test account", "test@example.test", true, IdentityStatus.Active, ["pwd"]))
                    : new Feedback<ResolvedIdentitySession>(false, "Invalid session.") { Key = "invalid_session" });
            default:
                throw new NotSupportedException(targetMethod?.Name);
        }
    }

    private static UserIdentity Account(Guid id) => new(id, "Test account", IdentityStatus.Active,
        "test@example.test", DateTimeOffset.UtcNow, null);
}
