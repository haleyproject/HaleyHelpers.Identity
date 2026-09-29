using Haley.Abstractions;

namespace Haley.Abstractions;
public interface IFederationAuthenticationService
{
    ValueTask<IFeedback<FederationStart>> BeginAsync(BeginFederationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<FederationHandoff>> CompleteAsync(CompleteSamlAuthenticationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<FederationHandoff>> CompleteExternalAsync(CompleteExternalAuthenticationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<IReadOnlyCollection<ProviderDiscovery>>> DiscoverAsync(ProviderDiscoveryRequest request, CancellationToken cancellationToken = default);
}
