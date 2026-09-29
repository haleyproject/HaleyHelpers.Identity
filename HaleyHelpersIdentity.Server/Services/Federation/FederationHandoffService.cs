using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Security;

namespace Haley.Services;

/// <summary>Redeems a verified provider proof. Compositions decide which session/token to issue.</summary>
public sealed class FederationHandoffService(IIdentityFederationStore store, IIdentityRecoveryAuthorization authorization, IIdentityFederationPolicy policy,
    ISecretEnvelopeProtector protector, ISecretTokenGenerator tokens, IIdentityUuidGenerator uuids,
    IIdentityClock clock, IIdentityVerificationMfaPolicy mfa)
{
    public async ValueTask<IFeedback<VerifiedFederatedAccount>> RedeemAsync(RedeemFederationHandoffRequest request,
        CancellationToken cancellationToken = default, string? requiredContext = null)
    {
        if (request.ApplicationId == Guid.Empty || string.IsNullOrWhiteSpace(request.Code) || request.Code.Length > 512 ||
            request.CodeVerifier is null || request.CodeVerifier.Length is < 43 or > 128 ||
            request.CodeVerifier.Any(value => !(char.IsAsciiLetterOrDigit(value) || value is '-' or '.' or '_' or '~')))
            return Fail(IdentityErrorCodes.InvalidRequest, 400);
        var codeHash = tokens.Hash(request.Code.Trim());
        var challenge = SHA256.HashData(Encoding.ASCII.GetBytes(request.CodeVerifier));
        var stored = await store.FindFederationHandoffAsync(request.ApplicationId, codeHash, challenge, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        if (stored is null) return Fail(IdentityErrorCodes.FederationRejected);
        VerifiedFederationAssertion? assertion;
        try
        {
            var plaintext = protector.Unprotect(stored.PayloadEncrypted, "haley.identity.federation.handoff.v1");
            try { assertion = JsonSerializer.Deserialize<VerifiedFederationAssertion>(plaintext); }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
        catch (Exception error) when (error is CryptographicException or JsonException or InvalidOperationException)
        { return Fail(IdentityErrorCodes.FederationRejected); }
        if (assertion is null || assertion.ApplicationId != request.ApplicationId || assertion.Context != stored.Context ||
            (requiredContext is not null && !string.Equals(requiredContext, assertion.Context, StringComparison.Ordinal)) ||
            !authorization.TryNormalizeContext(assertion.Context, out var context) ||
            !await authorization.HasActiveResourceAuthorityAsync(request.ApplicationId, context, cancellationToken).ConfigureAwait(false))
            return Fail(IdentityErrorCodes.FederationRejected);
        var provider = await store.FindProviderAsync(assertion.ProviderCode, cancellationToken).ConfigureAwait(false);
        if (provider is null || provider.ProviderId != assertion.ProviderId || provider.Status != IdentityRecordStatus.Active ||
            (provider.Protocol == FederationProtocol.Saml ? assertion.AuthenticationMethod != "saml" :
                provider.Protocol != FederationProtocol.SignedCallback || assertion.AuthenticationMethod != "external") ||
            !ProviderApplicationPolicy.Allows(provider.Configuration, request.ApplicationId, await policy.RequiresApplicationAllowlistAsync(provider.ProviderId, cancellationToken).ConfigureAwait(false)) ||
            assertion.Subject.Length is < 1 or > 500 || assertion.DisplayName.Length is < 1 or > 200)
            return Fail(IdentityErrorCodes.FederationRejected);
        var email = IdentityPolicy.TryNormalizeEmail(assertion.Email ?? string.Empty, out var normalized) ? normalized : null;
        var domain = email is null ? null : email[(email.LastIndexOf('@') + 1)..];
        var trustedEmail = assertion.EmailVerified && domain is not null && provider.AuthoritativeDomains.Contains(domain, StringComparer.Ordinal);
        var linked = await store.FindOrLinkFederatedIdentityAsync(new(uuids.NewUuid7(), provider.ProviderId, assertion.Subject,
            assertion.ClaimsPayload, email, email, assertion.DisplayName, true, trustedEmail, trustedEmail,
            assertion.AuthenticatedAt), cancellationToken).ConfigureAwait(false);
        if (linked is null) return Fail(IdentityErrorCodes.LinkVerificationRequired);
        if (linked.Identity.Status != IdentityStatus.Active || linked.Identity.PasswordChangeRequired)
            return Fail(IdentityErrorCodes.FederationRejected);
        var factors = await mfa.VerifyAsync(new(linked.Identity.UserId, linked.Identity.Username ?? string.Empty, request.ApplicationId,
            context, request.MfaKind, request.MfaMethodId, request.MfaCode), cancellationToken).ConfigureAwait(false);
        if (!factors.Status) return Fail(factors.Key ?? IdentityErrorCodes.MfaInvalid);
        // A failed factor does not burn the handoff. Only one concurrent successful redemption can consume it.
        var consumed = await store.ConsumeFederationHandoffAsync(request.ApplicationId, codeHash, challenge, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        if (consumed is null) return Fail(IdentityErrorCodes.FederationRejected);
        return new Feedback<VerifiedFederatedAccount>(true, "Federated identity verified.",
            new(linked, request.ApplicationId, context, [assertion.AuthenticationMethod, .. factors.Result ?? []]))
        { Source = "Haley.Identity.Federation" };
    }

    private static IFeedback<VerifiedFederatedAccount> Fail(string key, int code = 401) =>
        new Feedback<VerifiedFederatedAccount>(false, "Federated authentication was rejected.")
        { Key = key, Code = code, Source = "Haley.Identity.Federation" };
}
