namespace Haley.Services;

internal sealed class IdentityFederationService(IFederationAuthenticationService authentication,
    FederationHandoffService handoffs, IdentityService identity, IIdentityApplicationContext application) : IIdentityFederation
{
    public ValueTask<IFeedback<IReadOnlyCollection<ProviderDiscovery>>> DiscoverAsync(ProviderDiscoveryRequest request, CancellationToken cancellationToken = default) =>
        authentication.DiscoverAsync(request, cancellationToken);

    public ValueTask<IFeedback<FederationStart>> BeginAsync(BeginFederationRequest request, CancellationToken cancellationToken = default) =>
        (Matches(request.ApplicationId) && (application.OwnerContext is null || application.OwnerContext == request.Context)) ? authentication.BeginAsync(request, cancellationToken) : Rejected<FederationStart>();

    public ValueTask<IFeedback<FederationHandoff>> CompleteSamlAsync(CompleteSamlAuthenticationRequest request, CancellationToken cancellationToken = default) =>
        Matches(request.ApplicationId) ? authentication.CompleteAsync(request, cancellationToken) : Rejected<FederationHandoff>();

    public ValueTask<IFeedback<FederationHandoff>> CompleteExternalAsync(CompleteExternalAuthenticationRequest request, CancellationToken cancellationToken = default) =>
        Matches(request.ApplicationId) ? authentication.CompleteExternalAsync(request, cancellationToken) : Rejected<FederationHandoff>();

    public async ValueTask<IFeedback<OpaqueSession>> RedeemAsync(RedeemFederationHandoffRequest request, CancellationToken cancellationToken = default)
    {
        if (!Matches(request.ApplicationId)) return await Rejected<OpaqueSession>();
        var result = await handoffs.RedeemAsync(request, cancellationToken, application.OwnerContext).ConfigureAwait(false);
        if (!result.Status || result.Result is null) return new Feedback<OpaqueSession>(false, result.Message)
            { Key = result.Key, Code = result.Code, Source = result.Source };
        return await identity.StartVerifiedSessionAsync(result.Result.Account.Identity.UserId, null,
            result.Result.AuthenticationMethods, cancellationToken).ConfigureAwait(false);
    }

    private bool Matches(Guid? id) => id.HasValue && id.Value != Guid.Empty && id.Value == application.ApplicationId;
    private static ValueTask<IFeedback<T>> Rejected<T>() => ValueTask.FromResult<IFeedback<T>>(
        new Feedback<T>(false, "The application binding was rejected.") { Key = "invalid_application", Code = 403 });
}
