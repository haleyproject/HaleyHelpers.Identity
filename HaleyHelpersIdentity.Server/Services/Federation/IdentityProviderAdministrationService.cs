using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Abstractions;
using Haley.Models;
using Haley.Security;
using Microsoft.Extensions.Options;

namespace Haley.Services;
internal sealed class IdentityProviderAdministrationService(
    IIdentityFederationStore store,
    IIdentitySamlCertificateService certificates,
    IIdentityUuidGenerator uuids,
    IIdentityClock clock) : IIdentityProviderAdministrationService
{
    public ValueTask<IReadOnlyCollection<IdentityProviderInfo>> ListProvidersAsync(CancellationToken cancellationToken = default) => store.ListProvidersAsync(cancellationToken);
    public async ValueTask<IFeedback<IdentityProviderInfo>> UpsertProviderAsync(Guid? providerId, UpsertIdentityProviderRequest request, CancellationToken cancellationToken = default)
    {
        var code = request.Code?.Trim().Normalize().ToLowerInvariant() ?? string.Empty;
        var issuer = request.Issuer?.Trim() ?? string.Empty;
        var name = request.DisplayName?.Trim().Normalize() ?? string.Empty;
        var status = request.Status;
        if (code.Length is < 2 or > 100 || issuer.Length is < 3 or > 500 || name.Length is < 1 or > 200 || request.Configuration is null || request.Configuration.Length > 65536 || status is not (IdentityRecordStatus.Active or IdentityRecordStatus.Retired))
            return Failure<IdentityProviderInfo>(IdentityErrorCodes.InvalidRequest);
        string configuration;
        IReadOnlyCollection<string> certificateNames;
        try
        {
            var config = JsonNode.Parse(request.Configuration) as JsonObject ?? new JsonObject();
            if (config.ContainsKey("allowedClientIds")) return Failure<IdentityProviderInfo>(IdentityErrorCodes.InvalidRequest);
            var defaults = ProviderApplicationPolicy.DefaultApplications(config.ToJsonString());
            if (status == IdentityRecordStatus.Active && defaults.Count > 0)
            {
                var existing = await store.ListProvidersAsync(cancellationToken).ConfigureAwait(false);
                if (existing.Any(provider => provider.ProviderId != providerId && provider.Status == IdentityRecordStatus.Active &&
                    ProviderApplicationPolicy.DefaultApplications(provider.Configuration).Overlaps(defaults)))
                    return Failure<IdentityProviderInfo>(IdentityErrorCodes.FederationDefaultConflict);
            }
            if (config.ContainsKey("signingCertificates"))
                return Failure<IdentityProviderInfo>(IdentityErrorCodes.SamlCertificateInvalid);
            if (request.Protocol == FederationProtocol.Saml)
            {
                certificateNames = NormalizeCertificateNames(request.SigningCertificates);
                if (certificateNames.Count == 0 || certificateNames.Any(name => !certificates.Exists(name)))
                    return Failure<IdentityProviderInfo>(IdentityErrorCodes.SamlCertificateMissing);
                config["signingCertificates"] = new JsonArray(
                    certificateNames.Select(name => JsonValue.Create(name)).ToArray());
                _ = SamlProviderConfiguration.Parse(config.ToJsonString());
            }
            else
            {
                if (request.Protocol != FederationProtocol.SignedCallback)
                    return Failure<IdentityProviderInfo>(IdentityErrorCodes.InvalidRequest);
                var external = ExternalProviderConfiguration.Parse(config.ToJsonString());
                config["contractVersion"] = external.ContractVersion;
                if (request.SigningCertificates?.Count > 0)
                    return Failure<IdentityProviderInfo>(IdentityErrorCodes.SamlCertificateInvalid);
                certificateNames = [];
            }
            configuration = config.ToJsonString();
        }
        catch (Exception exception)when (exception is JsonException or InvalidOperationException or ArgumentException or FormatException or CryptographicException or KeyNotFoundException)
        {
            return Failure<IdentityProviderInfo>(IdentityErrorCodes.InvalidRequest);
        }

        var domains = NormalizeDomains(request.AuthoritativeDomains);
        var discoveryDomains = NormalizeDomains(request.DiscoveryDomains);
        if (domains.Concat(discoveryDomains).Any(value => value.Length > 253 || Uri.CheckHostName(value) != UriHostNameType.Dns))
            return Failure<IdentityProviderInfo>(IdentityErrorCodes.InvalidRequest);
        var normalized = request with
        {
            Code = code,
            Issuer = issuer,
            DisplayName = name,
            Status = status,
            AuthoritativeDomains = domains,
            DiscoveryDomains = discoveryDomains,
            Configuration = configuration,
            SigningCertificates = certificateNames
        };
        var result = await store.UpsertProviderAsync(providerId ?? uuids.NewUuid7(), normalized, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        return result is null ? Failure<IdentityProviderInfo>(IdentityErrorCodes.InvalidRequest) : new Feedback<IdentityProviderInfo>(true, "Identity provider saved.", result)
        {
            Source = "Haley.Identity.Federation"
        };
    }

    private static string[] NormalizeDomains(IReadOnlyCollection<string>? values) => (values ?? []).Select(value => value?.Trim().ToLowerInvariant() ?? string.Empty).Distinct(StringComparer.Ordinal).ToArray();

    private static IReadOnlyCollection<string> NormalizeCertificateNames(IReadOnlyCollection<string>? values)
    {
        var result = new List<string>();
        foreach (var value in values ?? [])
        {
            if (!SamlCertificateNames.TryNormalize(value, out var name))
                throw new InvalidOperationException("SAML certificate references must be managed names.");
            result.Add(name);
        }
        return result.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static IFeedback<T> Failure<T>(string key) => new Feedback<T>(false,
        key == IdentityErrorCodes.FederationDefaultConflict ? "Another active provider is already the default for one of these applications." : "Identity provider request was rejected.", default!)
    {
        Source = "Haley.Identity.Federation",
        Key = key,
        Code = key == IdentityErrorCodes.FederationDefaultConflict ? 409 : 400
    };
}
