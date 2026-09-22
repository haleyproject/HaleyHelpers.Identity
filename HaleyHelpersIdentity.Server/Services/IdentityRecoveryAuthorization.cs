using Microsoft.Extensions.Options;
namespace Haley.Services;
internal sealed class IdentityRecoveryAuthorization(IOptions<IdentityServerOptions> options) : IIdentityRecoveryAuthorization
{
    public bool TryNormalizeContext(string? value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        return normalized.Length is > 0 and <= 200 && !normalized.Any(char.IsControl);
    }
    public ValueTask<bool> HasActiveResourceAuthorityAsync(Guid applicationId, string context, CancellationToken cancellationToken) => ValueTask.FromResult(applicationId != Guid.Empty);
    public ValueTask<bool> IsReturnUriAllowedAsync(Guid applicationId, string context, string returnUri, CancellationToken cancellationToken) =>
        ValueTask.FromResult(options.Value.AllowedReturnUris.TryGetValue(applicationId.ToString("D"), out var allowed) && allowed.Contains(returnUri, StringComparer.Ordinal));
}
