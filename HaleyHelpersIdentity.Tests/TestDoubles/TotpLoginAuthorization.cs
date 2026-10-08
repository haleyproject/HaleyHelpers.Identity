using Haley.Abstractions;

namespace Haley.Identity.Tests;

internal sealed class TotpLoginAuthorization : IIdentityRecoveryAuthorization
{
    public bool Permitted { get; set; } = true;
    public bool TryNormalizeContext(string? value, out string normalized) { normalized = value ?? "haley.identity"; return true; }
    public ValueTask<bool> HasActiveResourceAuthorityAsync(Guid applicationId, string context, CancellationToken cancellationToken) => ValueTask.FromResult(Permitted);
    public ValueTask<bool> IsReturnUriAllowedAsync(Guid applicationId, string context, string uri, CancellationToken cancellationToken) => throw new NotSupportedException();
}
