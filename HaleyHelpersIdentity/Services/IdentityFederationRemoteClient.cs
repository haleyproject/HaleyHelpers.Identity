using Haley.Enums;

namespace Haley.Services;

public sealed class IdentityFederationRemoteClient(IdentityRemoteTransport transport) : IIdentityFederation
{
    public ValueTask<IFeedback<IReadOnlyCollection<ProviderDiscovery>>> DiscoverAsync(ProviderDiscoveryRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<IReadOnlyCollection<ProviderDiscovery>>("DiscoverIdentityProviders", "federation/discovery", Method.POST, request, cancellationToken);
    public ValueTask<IFeedback<FederationStart>> BeginAsync(BeginFederationRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<FederationStart>("BeginFederation", "federation/attempts", Method.POST, request, cancellationToken);
    public ValueTask<IFeedback<FederationHandoff>> CompleteSamlAsync(CompleteSamlAuthenticationRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<FederationHandoff>("CompleteSamlFederation", "federation/saml/completion", Method.POST, request, cancellationToken);
    public ValueTask<IFeedback<FederationHandoff>> CompleteExternalAsync(CompleteExternalAuthenticationRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<FederationHandoff>("CompleteExternalFederation", "federation/external/completion", Method.POST, request, cancellationToken);
    public ValueTask<IFeedback<OpaqueSession>> RedeemAsync(RedeemFederationHandoffRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<OpaqueSession>("RedeemFederation", "federation/handoffs", Method.POST, request, cancellationToken);
}
