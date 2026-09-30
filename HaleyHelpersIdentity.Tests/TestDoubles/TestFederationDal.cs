using System.Security.Cryptography;
using Haley.Abstractions;
using Haley.Models;

namespace Haley.Tests;

internal sealed class TestFederationDal : IIdentityFederationStore, IIdentityRecoveryAuthorization, IIdentityVerificationMfaPolicy, IIdentityFederationPolicy
{
    public bool RedirectAllowed { get; init; }
    public bool ResourceAllowed { get; set; } = true;
    public bool RequireApplicationAllowlist { get; set; }
    public List<StoredIdentityProvider> AdditionalProviders { get; } = [];
    public ValueTask<bool> RequiresApplicationAllowlistAsync(Guid providerId, CancellationToken cancellationToken) => ValueTask.FromResult(RequireApplicationAllowlist);
    public CreateFederationAttemptCommand? CreatedRequest { get; private set; }
    public bool Completed { get; private set; }
    public bool Redeemed { get; private set; }
    public bool RequireMfa { get; set; }
    public string AccountUsername { get; set; } = "stored@example.com";
    public string? LastMfaEmail { get; private set; }
    public Guid ProviderId { get; set; } = SamlAuthenticationEdgeTests.ProviderId;
    public IdentityRecordStatus ProviderStatus { get; set; } = IdentityRecordStatus.Active;
    public IdentityStatus AccountStatus { get; set; } = IdentityStatus.Active;
    public FederationProtocol Protocol { get; set; } = FederationProtocol.Saml;
    public IReadOnlyCollection<string> AuthoritativeDomains { get; set; } = ["example.com"];
    public IReadOnlyCollection<string> DiscoveryDomains { get; set; } = ["example.com"];
    public LinkFederatedIdentityCommand? LastLink { get; private set; }
    public string Configuration { get; set; } = """
        {"ssoUrl":"https://idp.example/sso","acsUrl":"https://auth.example/saml/acs","spEntityId":"https://auth.example/security",
         "signingCertificates":["certificate-is-loaded-only-during-completion.cer"]}
        """;
    private readonly object gate = new();
    private readonly HashSet<string> replay = [];
    private CompleteFederationAttemptCommand? handoff;
    public ValueTask<StoredIdentityProvider?> FindProviderAsync(string code, CancellationToken ct) => ValueTask.FromResult<StoredIdentityProvider?>(
        code == "corporate" ? new(7, ProviderId, code, Protocol, "https://idp.example/issuer", "Corporate",
            ProviderStatus, Configuration, AuthoritativeDomains, SamlAuthenticationEdgeTests.Now, [], DiscoveryDomains) : AdditionalProviders.SingleOrDefault(provider => provider.Code == code));
    public async ValueTask<IReadOnlyCollection<IdentityProviderInfo>> ListProvidersAsync(CancellationToken ct)
    {
        var p = (await FindProviderAsync("corporate", ct))!;
        return new[] { p }.Concat(AdditionalProviders).Select(provider => new IdentityProviderInfo(provider.ProviderId, provider.Code, provider.Protocol,
            provider.Issuer, provider.DisplayName, provider.Status, provider.Configuration, provider.AuthoritativeDomains, provider.ModifiedAt, [], provider.DiscoveryDomains)).ToArray();
    }
    public ValueTask<IdentityProviderInfo?> UpsertProviderAsync(Guid id, UpsertIdentityProviderRequest request, DateTimeOffset now, CancellationToken ct) =>
        ValueTask.FromResult<IdentityProviderInfo?>(new(id, request.Code, request.Protocol, request.Issuer, request.DisplayName, request.Status,
            request.Configuration, request.AuthoritativeDomains ?? [], now, request.SigningCertificates, request.DiscoveryDomains));
    public bool TryNormalizeContext(string? value, out string normalized) { normalized = value?.Trim() ?? string.Empty; return normalized.Length > 0; }
    public ValueTask<bool> HasActiveResourceAuthorityAsync(Guid id, string context, CancellationToken ct) => ValueTask.FromResult(ResourceAllowed);
    public ValueTask<bool> IsReturnUriAllowedAsync(Guid id, string context, string uri, CancellationToken ct) =>
        ValueTask.FromResult(RedirectAllowed && id == SamlAuthenticationEdgeTests.ClientId && context == "product-api" && uri == SamlAuthenticationEdgeTests.Callback);
    public ValueTask<bool> CreateFederationAttemptAsync(CreateFederationAttemptCommand command, CancellationToken ct)
    { CreatedRequest = command; return ValueTask.FromResult(true); }
    public ValueTask<StoredFederationAttempt?> FindFederationAttemptAsync(Guid id, DateTimeOffset now, CancellationToken ct)
    {
        var r = CreatedRequest;
        return ValueTask.FromResult<StoredFederationAttempt?>(r is null || r.RequestId != id || Completed || r.ExpiresAt <= now || ProviderStatus != IdentityRecordStatus.Active ? null :
            new(1, r.RequestId, 7, SamlAuthenticationEdgeTests.ProviderId, "corporate", "https://idp.example/issuer", Configuration,
                r.ApplicationId, r.Context, r.ProtocolRequestId, r.ReturnUri, r.State, r.CodeChallenge, r.ExpiresAt, Protocol));
    }
    public ValueTask<bool> TryConsumeFederationReplayAsync(long provider, byte[] response, byte[] assertion, DateTimeOffset expiry, DateTimeOffset now, CancellationToken ct)
    { lock (gate) return ValueTask.FromResult(replay.Add(Convert.ToHexString(assertion))); }
    public ValueTask<bool> CompleteFederationAttemptAsync(CompleteFederationAttemptCommand command, CancellationToken ct)
    {
        lock (gate)
        {
            if (Completed) return ValueTask.FromResult(false);
            handoff = command with { PayloadEncrypted = command.PayloadEncrypted.ToArray() };
            Completed = true;
            return ValueTask.FromResult(true);
        }
    }
    public ValueTask<StoredFederationHandoff?> FindFederationHandoffAsync(Guid app, byte[] hash, byte[] challenge, DateTimeOffset now, CancellationToken ct)
    {
        var h = handoff; var r = CreatedRequest;
        return ValueTask.FromResult<StoredFederationHandoff?>(h is null || r is null || Redeemed || app != r.ApplicationId || h.ExpiresAt <= now ||
            !CryptographicOperations.FixedTimeEquals(hash, h.CodeHash) || !CryptographicOperations.FixedTimeEquals(challenge, r.CodeChallenge)
            ? null : new(h.HandoffId, app, r.Context, h.PayloadEncrypted, r.CodeChallenge, h.ExpiresAt));
    }
    public ValueTask<StoredFederationHandoff?> ConsumeFederationHandoffAsync(Guid app, byte[] hash, byte[] challenge, DateTimeOffset now, CancellationToken ct)
    {
        lock (gate)
        {
            var found = FindFederationHandoffAsync(app, hash, challenge, now, ct).Result;
            if (found is not null) Redeemed = true;
            return ValueTask.FromResult(found);
        }
    }
    public ValueTask<FederatedIdentityLinkResult?> FindOrLinkFederatedIdentityAsync(LinkFederatedIdentityCommand command, CancellationToken ct)
    {
        LastLink = command;
        return ValueTask.FromResult<FederatedIdentityLinkResult?>(new(5, new(Guid.Parse("44444444-4444-4444-8444-444444444444"),
            command.DisplayName, AccountStatus, AccountUsername, command.AuthenticatedAt, command.AuthenticatedAt), false, true));
    }
    public ValueTask<IFeedback<IReadOnlyCollection<string>>> VerifyAsync(VerificationMfaRequest request, CancellationToken ct)
    {
        LastMfaEmail = request.Email;
        return ValueTask.FromResult<IFeedback<IReadOnlyCollection<string>>>(RequireMfa && request.Code != "123456"
            ? new Feedback<IReadOnlyCollection<string>>(false, "A second factor is required.") { Key = "mfa_required", Code = 401 }
            : new Feedback<IReadOnlyCollection<string>>(true, "Factors verified.", RequireMfa ? ["totp"] : []));
    }
}
