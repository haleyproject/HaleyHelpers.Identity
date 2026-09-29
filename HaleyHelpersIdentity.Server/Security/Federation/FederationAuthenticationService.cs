using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using Haley.Abstractions;
using Haley.Models;
using Haley.Security;
using Haley.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Haley.Security;
internal sealed class FederationAuthenticationService(
    IIdentityFederationStore store,
    IIdentityRecoveryAuthorization authorization,
    IIdentityFederationPolicy policy,
    IIdentitySamlCertificateService certificateStore,
    SamlAssertionValidator validator,
    ISecretEnvelopeProtector protector,
    ISecretTokenGenerator tokens,
    IIdentityUuidGenerator uuids,
    IIdentityClock clock,
    IOptions<IdentityServerOptions> options) : IFederationAuthenticationService
{
    private const string Source = "Haley.Identity.Federation";
    private const string HandoffPurpose = "haley.identity.federation.handoff.v1";
    public async ValueTask<IFeedback<FederationStart>> BeginAsync(BeginFederationRequest request, CancellationToken cancellationToken = default)
    {
        if (request.ApplicationId == Guid.Empty || string.IsNullOrWhiteSpace(request.ProviderCode) ||
            string.IsNullOrWhiteSpace(request.State) || request.State.Length is < 16 or > 200 || request.State.Any(char.IsControl) ||
            !authorization.TryNormalizeContext(request.Context, out var context) || !TryAbsoluteUri(request.ReturnUri, out var returnUri) ||
            string.IsNullOrWhiteSpace(request.CodeChallenge)) return Fail<FederationStart>(IdentityErrorCodes.InvalidRequest);
        byte[] challenge;
        try { challenge = request.CodeChallenge.Trim().SafeBase64Decode(); }
        catch (FormatException) { return Fail<FederationStart>(IdentityErrorCodes.InvalidRequest); }
        if (challenge.Length != 32) return Fail<FederationStart>(IdentityErrorCodes.InvalidRequest);
        var provider = await store.FindProviderAsync(request.ProviderCode.Trim().ToLowerInvariant(), cancellationToken).ConfigureAwait(false);
        if (provider is null || provider.Status != IdentityRecordStatus.Active ||
            provider.Protocol is not (FederationProtocol.Saml or FederationProtocol.SignedCallback) ||
            !ProviderApplicationPolicy.Allows(provider.Configuration, request.ApplicationId, await policy.RequiresApplicationAllowlistAsync(provider.ProviderId, cancellationToken).ConfigureAwait(false)))
            return Fail<FederationStart>(IdentityErrorCodes.FederationRejected);
        if (!await authorization.HasActiveResourceAuthorityAsync(request.ApplicationId, context, cancellationToken).ConfigureAwait(false) ||
            !await authorization.IsReturnUriAllowedAsync(request.ApplicationId, context, returnUri.AbsoluteUri, cancellationToken).ConfigureAwait(false))
            return Fail<FederationStart>(IdentityErrorCodes.InvalidClientResource);
        var now = clock.UtcNow;
        var expires = now.AddSeconds(Math.Clamp(options.Value.Federation.RequestValiditySeconds, 60, 900));
        var requestId = uuids.NewUuid7();
        var protocolId = "_" + requestId.ToString("N");
        FederationStart start;
        try
        {
            if (provider.Protocol == FederationProtocol.Saml)
            {
                var config = SamlProviderConfiguration.Parse(provider.Configuration);
                var encoded = DeflateAndEncode(BuildAuthenticationRequest(protocolId, now, config.AcsUrl.AbsoluteUri, config.SpEntityId, config.SsoUrl.AbsoluteUri));
                var url = config.SsoUrl.AbsoluteUri + (config.SsoUrl.Query.Length > 0 ? "&" : "?") + "SAMLRequest=" + Uri.EscapeDataString(encoded) + "&RelayState=" + requestId.ToString("N");
                start = new(requestId, config.SsoUrl.AbsoluteUri, encoded, requestId.ToString("N"), expires, url, provider.Protocol);
            }
            else
            {
                var config = ExternalProviderConfiguration.Parse(provider.Configuration);
                var url = config.AuthorizationUrl.AbsoluteUri + (config.AuthorizationUrl.Query.Length > 0 ? "&" : "?") + "attempt=" + requestId.ToString("N") + "&callback=" + Uri.EscapeDataString(config.CallbackUrl.AbsoluteUri);
                start = new(requestId, config.AuthorizationUrl.AbsoluteUri, string.Empty, requestId.ToString("N"), expires, url, provider.Protocol);
            }
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or FormatException or CryptographicException or KeyNotFoundException)
        { return Fail<FederationStart>(IdentityErrorCodes.FederationRejected); }
        if (!await store.CreateFederationAttemptAsync(new(requestId, provider.LocalProviderId, request.ApplicationId, context, protocolId, returnUri.AbsoluteUri, request.State, challenge, now, expires), cancellationToken).ConfigureAwait(false))
            return Fail<FederationStart>(IdentityErrorCodes.IdentityUnavailable);
        return Ok(start);
    }

    public async ValueTask<IFeedback<FederationHandoff>> CompleteAsync(CompleteSamlAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParseExact(request.RelayState?.Trim(), "N", out var requestId) || string.IsNullOrWhiteSpace(request.SamlResponse) || request.SamlResponse.Length > 350000)
            return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
        var stored = await store.FindFederationAttemptAsync(requestId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        if (stored is null || stored.Protocol != FederationProtocol.Saml ||
            (request.ApplicationId.HasValue && request.ApplicationId.Value != stored.ApplicationId))
            return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
        SamlProviderConfiguration configuration;
        IReadOnlyCollection<X509Certificate2> loadedCertificates;
        try
        {
            configuration = SamlProviderConfiguration.Parse(stored.ProviderConfiguration);
            loadedCertificates = configuration.LoadCertificates(certificateStore);
        }
        catch (Exception exception)when (exception is JsonException or InvalidOperationException or CryptographicException or IOException or FormatException)
        {
            return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
        }

        ValidatedSamlAssertion assertion;
        try
        {
            assertion = await validator.ValidateAsync(request.SamlResponse, new(loadedCertificates, stored.ProviderIssuer, configuration.SpEntityId, configuration.AcsUrl.AbsoluteUri, stored.ProtocolRequestId, clock.UtcNow), configuration.Validation, new SamlReplayStore(store, stored.LocalProviderId, clock), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)when (exception is InvalidDataException or InvalidOperationException or CryptographicException or XmlException)
        {
            return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
        }
        finally
        {
            foreach (var certificate in loadedCertificates)
                certificate.Dispose();
        }

        var email = FindClaim(assertion.Claims, configuration.EmailClaim, ClaimTypes.Email, "email", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        var displayName = FindClaim(assertion.Claims, configuration.DisplayNameClaim, ClaimTypes.Name, "name", "displayName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name") ?? email ?? assertion.Subject;
        var exchange = new VerifiedFederationAssertion(stored.ApplicationId, stored.Context, stored.ProviderId, stored.ProviderCode, assertion.Subject, email, displayName, JsonSerializer.Serialize(assertion.Claims.GroupBy(claim => claim.Type, StringComparer.Ordinal).ToDictionary(group => group.Key, group => group.Select(claim => claim.Value).ToArray(), StringComparer.Ordinal)), assertion.AssertionId, clock.UtcNow, "saml");
        return await CompleteProofAsync(stored, exchange, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IFeedback<FederationHandoff>> CompleteExternalAsync(CompleteExternalAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParseExact(request.Attempt?.Trim(), "N", out var id)) return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
        var attempt = await store.FindFederationAttemptAsync(id, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        if (attempt is null || attempt.Protocol != FederationProtocol.SignedCallback ||
            (request.ApplicationId.HasValue && request.ApplicationId != attempt.ApplicationId))
            return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
        try
        {
            var config = ExternalProviderConfiguration.Parse(attempt.ProviderConfiguration);
            var token = ExternalAssertionValidator.Validate(request.Assertion, attempt, config, clock.UtcNow);
            var responseHash = SHA256.HashData(Encoding.UTF8.GetBytes(request.Assertion));
            var assertionHash = SHA256.HashData(Encoding.UTF8.GetBytes(token.Id));
            if (!await store.TryConsumeFederationReplayAsync(attempt.LocalProviderId, responseHash, assertionHash,
                new DateTimeOffset(token.ValidTo, TimeSpan.Zero), clock.UtcNow, cancellationToken).ConfigureAwait(false))
                return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
            var email = token.Payload.TryGetValue("email", out var emailValue) ? emailValue?.ToString() : null;
            var name = token.Payload.TryGetValue("name", out var nameValue) ? nameValue?.ToString() : null;
            var emailVerified = token.Payload.TryGetValue("email_verified", out var verified) && verified is true;
            return await CompleteProofAsync(attempt, new(attempt.ApplicationId, attempt.Context, attempt.ProviderId, attempt.ProviderCode,
                token.Subject, email, name ?? email ?? token.Subject, token.Payload.SerializeToJson(), token.Id,
                clock.UtcNow, "external", emailVerified), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is Microsoft.IdentityModel.Tokens.SecurityTokenException or JsonException or
            InvalidOperationException or ArgumentException or FormatException or CryptographicException or KeyNotFoundException)
        { return Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected); }
    }

    public async ValueTask<IFeedback<IReadOnlyCollection<ProviderDiscovery>>> DiscoverAsync(ProviderDiscoveryRequest request, CancellationToken cancellationToken = default)
    {
        var value = request.EmailOrDomain?.Trim().ToLowerInvariant() ?? string.Empty;
        var domain = value.Contains('@') ? value[(value.LastIndexOf('@') + 1)..] : value;
        if (domain.Length is < 1 or > 253 || Uri.CheckHostName(domain) != UriHostNameType.Dns)
            return Fail<IReadOnlyCollection<ProviderDiscovery>>(IdentityErrorCodes.InvalidRequest);
        var providers = await store.ListProvidersAsync(cancellationToken).ConfigureAwait(false);
        return Ok<IReadOnlyCollection<ProviderDiscovery>>(providers.Where(provider => provider.Status == IdentityRecordStatus.Active &&
            (provider.DiscoveryDomains ?? []).Contains(domain, StringComparer.Ordinal)).Select(provider => new ProviderDiscovery(provider.Code, provider.DisplayName, provider.Protocol)).ToArray());
    }

    private async ValueTask<IFeedback<FederationHandoff>> CompleteProofAsync(StoredFederationAttempt stored,
        VerifiedFederationAssertion exchange, CancellationToken cancellationToken)
    {
        byte[] encrypted;
        try
        {
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(exchange);
            try { encrypted = protector.Protect(plaintext, HandoffPurpose); }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
        catch (InvalidOperationException)
        {
            return Fail<FederationHandoff>(IdentityErrorCodes.SigningUnavailable);
        }

        var code = tokens.Generate();
        var now = clock.UtcNow;
        var expires = now.AddSeconds(Math.Clamp(options.Value.Federation.HandoffValiditySeconds, 30, 300));
        var completed = await store.CompleteFederationAttemptAsync(new(stored.LocalRequestId, uuids.NewUuid7(), code.Hash, encrypted, now, expires), cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(encrypted);
        return completed ? Ok(new FederationHandoff(stored.ReturnUri, code.Value, expires, stored.State)) : Fail<FederationHandoff>(IdentityErrorCodes.FederationRejected);
    }

    private static string BuildAuthenticationRequest(string id, DateTimeOffset issuedAt, string acsUrl, string issuer, string destination)
    {
        var builder = new StringBuilder(768);
        using var writer = XmlWriter.Create(builder, new XmlWriterSettings { OmitXmlDeclaration = true, Encoding = Encoding.UTF8 });
        writer.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
        writer.WriteAttributeString("ID", id);
        writer.WriteAttributeString("Version", "2.0");
        writer.WriteAttributeString("IssueInstant", issuedAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture));
        writer.WriteAttributeString("Destination", destination);
        writer.WriteAttributeString("AssertionConsumerServiceURL", acsUrl);
        writer.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        writer.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
        writer.WriteString(issuer);
        writer.WriteEndElement();
        writer.WriteEndElement();
        writer.Flush();
        return builder.ToString();
    }

    private static string DeflateAndEncode(string value)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            deflate.Write(Encoding.UTF8.GetBytes(value));
        return Convert.ToBase64String(output.ToArray());
    }

    private static string? FindClaim(IEnumerable<Claim> claims, string? configured, params string[] candidates)
    {
        var names = string.IsNullOrWhiteSpace(configured) ? candidates : [configured, ..candidates];
        return claims.FirstOrDefault(claim => names.Contains(claim.Type, StringComparer.OrdinalIgnoreCase))?.Value;
    }

    private static bool TryAbsoluteUri(string? value, out Uri uri)
    {
        if (Uri.TryCreate(value?.Trim(), UriKind.Absolute, out uri!) && (uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) && string.IsNullOrEmpty(uri.Fragment) && string.IsNullOrEmpty(uri.UserInfo))
            return true;
        uri = null!;
        return false;
    }

    private static IFeedback<T> Ok<T>(T value) => new Feedback<T>(true, "SAML operation completed.", value)
    {
        Source = Source
    };
    private static IFeedback<T> Fail<T>(string code) => new Feedback<T>(false, "SAML operation failed.", default!)
    {
        Source = Source,
        Key = code
    };
}
