using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Haley.Security;

internal static class ExternalAssertionValidator
{
    internal static JwtSecurityToken Validate(string assertion, StoredFederationAttempt attempt,
        ExternalProviderConfiguration provider, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(assertion) || assertion.Length > 32768)
            throw new SecurityTokenValidationException("The provider assertion is missing or too large.");
        var principal = JWTUtil.ValidateToken(assertion, new TokenValidationParameters
        {
            RequireSignedTokens = true, RequireExpirationTime = true,
            ValidateIssuerSigningKey = true, IssuerSigningKeys = provider.LoadKeys(),
            TryAllIssuerSigningKeys = false, ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidTypes = [SignedCallbackContract.TokenType],
            ValidateIssuer = true, ValidIssuer = attempt.ProviderIssuer,
            ValidateAudience = true, ValidAudience = provider.Audience,
            ValidateLifetime = true, ClockSkew = TimeSpan.Zero,
            LifetimeValidator = (notBefore, expires, _, _) => expires.HasValue && expires.Value > now.UtcDateTime &&
                (!notBefore.HasValue || notBefore.Value <= now.UtcDateTime) &&
                expires.Value <= now.AddSeconds(provider.MaximumAssertionSeconds).UtcDateTime
        }, out var validated);
        if (principal is null || validated is not JwtSecurityToken token ||
            string.IsNullOrWhiteSpace(token.Header.Kid) || !provider.PublicKeys.ContainsKey(token.Header.Kid) ||
            token.Subject is not { Length: > 0 and <= 500 } || string.IsNullOrWhiteSpace(token.Id) || token.Id.Length > 200 ||
            !token.Payload.TryGetValue("attempt", out var correlation) || !Guid.TryParseExact(correlation?.ToString(), "N", out var id) || id != attempt.RequestId ||
            !token.Payload.TryGetValue("iat", out var issued) || !long.TryParse(issued?.ToString(), out var seconds) ||
            seconds > now.ToUnixTimeSeconds() || seconds < now.AddSeconds(-provider.MaximumAssertionSeconds).ToUnixTimeSeconds() ||
            token.ValidTo > DateTimeOffset.FromUnixTimeSeconds(seconds).AddSeconds(provider.MaximumAssertionSeconds).UtcDateTime)
            throw new SecurityTokenValidationException("The provider assertion was rejected.");
        // An absent version is the original v1 contract. An explicit version must be a matching JSON integer.
        if (token.Payload.TryGetValue("contractVersion", out var contractVersion) &&
            !((contractVersion is int intVersion && intVersion == provider.ContractVersion) ||
              (contractVersion is long longVersion && longVersion == provider.ContractVersion)))
            throw new SecurityTokenValidationException("The signed callback contract version was rejected.");
        return token;
    }
}
