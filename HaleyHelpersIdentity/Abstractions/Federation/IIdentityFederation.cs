namespace Haley.Abstractions;

/// <summary>Reusable federation API registered by AddHaleyIdentity for embedded and remote execution.</summary>
public interface IIdentityFederation
{
    ValueTask<IFeedback<IReadOnlyCollection<ProviderDiscovery>>> DiscoverAsync(ProviderDiscoveryRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<FederationStart>> BeginAsync(BeginFederationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<FederationHandoff>> CompleteSamlAsync(CompleteSamlAuthenticationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<FederationHandoff>> CompleteExternalAsync(CompleteExternalAuthenticationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<OpaqueSession>> RedeemAsync(RedeemFederationHandoffRequest request, CancellationToken cancellationToken = default);
}
