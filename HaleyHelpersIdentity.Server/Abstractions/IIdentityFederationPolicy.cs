namespace Haley.Abstractions;

/// <summary>Composition-owned restrictions beyond provider proof verification.</summary>
public interface IIdentityFederationPolicy
{
    ValueTask<bool> RequiresApplicationAllowlistAsync(Guid providerId, CancellationToken cancellationToken);
}
