namespace Haley.Abstractions;
public interface IIdentityFederationStore
{
    ValueTask<StoredIdentityProvider?> FindProviderAsync(string code, CancellationToken cancellationToken);
    ValueTask<IReadOnlyCollection<IdentityProviderInfo>> ListProvidersAsync(CancellationToken cancellationToken);
    ValueTask<IdentityProviderInfo?> UpsertProviderAsync(Guid providerId, UpsertIdentityProviderRequest request, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<FederatedIdentityLinkResult?> FindOrLinkFederatedIdentityAsync(LinkFederatedIdentityCommand command, CancellationToken cancellationToken);
    ValueTask<bool> CreateFederationAttemptAsync(CreateFederationAttemptCommand command, CancellationToken cancellationToken);
    ValueTask<StoredFederationAttempt?> FindFederationAttemptAsync(Guid requestId, DateTimeOffset evaluatedAt, CancellationToken cancellationToken);
    ValueTask<bool> TryConsumeFederationReplayAsync(long localProviderId, byte[] responseHash, byte[] assertionHash, DateTimeOffset expiresAt, DateTimeOffset createdAt, CancellationToken cancellationToken);
    ValueTask<bool> CompleteFederationAttemptAsync(CompleteFederationAttemptCommand command, CancellationToken cancellationToken);
    ValueTask<StoredFederationHandoff?> ConsumeFederationHandoffAsync(Guid clientId, byte[] codeHash, byte[] codeChallenge, DateTimeOffset now, CancellationToken cancellationToken);
    ValueTask<StoredFederationHandoff?> FindFederationHandoffAsync(Guid applicationId, byte[] codeHash, byte[] codeChallenge, DateTimeOffset now, CancellationToken cancellationToken);
}
