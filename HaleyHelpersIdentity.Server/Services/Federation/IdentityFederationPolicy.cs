namespace Haley.Services;

internal sealed class IdentityFederationPolicy : IIdentityFederationPolicy
{
    public ValueTask<bool> RequiresApplicationAllowlistAsync(Guid providerId, CancellationToken cancellationToken) => ValueTask.FromResult(false);
}
