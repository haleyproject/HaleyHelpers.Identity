using Haley.Abstractions;

namespace Haley.Abstractions;
public interface IIdentityProviderAdministrationService
{
    ValueTask<IReadOnlyCollection<IdentityProviderInfo>> ListProvidersAsync(CancellationToken cancellationToken = default);
    ValueTask<IFeedback<IdentityProviderInfo>> UpsertProviderAsync(Guid? providerId, UpsertIdentityProviderRequest request, CancellationToken cancellationToken = default);
}
