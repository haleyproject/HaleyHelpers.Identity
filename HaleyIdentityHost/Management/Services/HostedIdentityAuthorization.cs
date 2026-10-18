using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.Options;

namespace Haley.Hosting;

/// <summary>Standalone hosted flows require a currently active registered application.</summary>
internal sealed class HostedIdentityAuthorization(IdentityApplicationRegistry registry,
    IOptions<IdentityServerOptions> options) : IIdentityRecoveryAuthorization
{
    public bool TryNormalizeContext(string? value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        return normalized.Length is > 0 and <= 200 && !normalized.Any(char.IsControl);
    }
    public ValueTask<bool> HasActiveResourceAuthorityAsync(Guid applicationId, string context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(registry.List().Any(app => app.ApplicationId == applicationId &&
            app.Status == IdentityRecordStatus.Active && app.KeyIds.Count > 0));
    public ValueTask<bool> IsReturnUriAllowedAsync(Guid applicationId, string context, string returnUri, CancellationToken cancellationToken) =>
        ValueTask.FromResult(options.Value.AllowedReturnUris.TryGetValue(applicationId.ToString("D"), out var allowed) &&
            allowed.Contains(returnUri, StringComparer.Ordinal));
}
