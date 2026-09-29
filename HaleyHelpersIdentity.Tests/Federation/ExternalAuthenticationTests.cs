using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Haley.Tests;

public sealed class ExternalAuthenticationTests : IDisposable
{
    private const string Verifier = "a-valid-pkce-verifier-with-more-than-forty-three-characters-0123456789";
    private readonly RSA key = RSA.Create(2048);
    private static DateTimeOffset Now => SamlAuthenticationEdgeTests.Now;

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("attempt")]
    [InlineData("expired")]
    [InlineData("lifetime")]
    [InlineData("type")]
    [InlineData("key")]
    [InlineData("signature")]
    [InlineData("algorithm")]
    public async Task InvalidProofNeverCompletesAttempt(string fault)
    {
        var store = Store();
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        var started = await edge.BeginAsync(Start());
        Assert.True(started.Status);
        var completed = await edge.CompleteExternalAsync(new(started.Result!.RelayState, Assertion(started.Result.RequestId, fault)));
        Assert.False(completed.Status);
        Assert.False(store.Completed);
    }

    [Fact]
    public async Task ValidProofProducesOneUsePkceBoundHandoffAndRetriesMissingMfa()
    {
        var store = Store(); store.RequireMfa = true;
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        var started = await edge.BeginAsync(Start());
        Assert.True(started.Status);
        Assert.Contains("attempt=" + started.Result!.RelayState, started.Result.AuthorizationUrl);
        Assert.DoesNotContain(SamlAuthenticationEdgeTests.Callback, started.Result.AuthorizationUrl);
        var proof = new CompleteExternalAuthenticationRequest(started.Result.RelayState, Assertion(started.Result.RequestId));
        var completed = await edge.CompleteExternalAsync(proof);
        Assert.True(completed.Status);
        Assert.Equal(SamlAuthenticationEdgeTests.Callback, completed.Result!.ReturnUri);
        Assert.Equal(Start().State, completed.Result.State);
        Assert.False((await edge.CompleteExternalAsync(proof)).Status);
        var handoffs = services.GetRequiredService<FederationHandoffService>();
        var request = new RedeemFederationHandoffRequest(SamlAuthenticationEdgeTests.ClientId, completed.Result.Code, Verifier);
        Assert.False((await handoffs.RedeemAsync(request with { ApplicationId = Guid.NewGuid() })).Status);
        Assert.False((await handoffs.RedeemAsync(request with { CodeVerifier = new string('x', 64) })).Status);
        Assert.False((await handoffs.RedeemAsync(request, requiredContext: "another-resource")).Status);
        var missingMfa = await handoffs.RedeemAsync(request);
        Assert.Equal("mfa_required", missingMfa.Key);
        Assert.False(store.Redeemed);
        var accepted = await handoffs.RedeemAsync(request with { MfaKind = MfaKind.Totp, MfaCode = "123456" });
        Assert.True(accepted.Status);
        Assert.Contains("totp", accepted.Result!.AuthenticationMethods);
        Assert.True(store.LastLink!.EmailVerified);
        Assert.Equal("stored@example.com", store.LastMfaEmail);
        Assert.False((await handoffs.RedeemAsync(request)).Status);
    }

    [Fact]
    public async Task DiscoveryDoesNotAuthorizeEmailLinkingAndRetiredAccountsAreRejected()
    {
        var store = Store(); store.AuthoritativeDomains = [];
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        Assert.Single((await edge.DiscoverAsync(new("user@example.com"))).Result!);
        var started = await edge.BeginAsync(Start());
        var completed = await edge.CompleteExternalAsync(new(started.Result!.RelayState, Assertion(started.Result.RequestId)));
        store.AccountStatus = IdentityStatus.Retired;
        var rejected = await services.GetRequiredService<FederationHandoffService>().RedeemAsync(new(SamlAuthenticationEdgeTests.ClientId, completed.Result!.Code, Verifier));
        Assert.False(rejected.Status);
        Assert.False(store.LastLink!.AutoLink);
        Assert.False(store.LastLink.EmailVerified);
    }

    [Fact]
    public async Task ProviderRetirementIsRecheckedAtRedemption()
    {
        var store = Store();
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        var started = await edge.BeginAsync(Start());
        var completed = await edge.CompleteExternalAsync(new(started.Result!.RelayState, Assertion(started.Result.RequestId)));
        store.ProviderStatus = IdentityRecordStatus.Retired;
        Assert.False((await services.GetRequiredService<FederationHandoffService>().RedeemAsync(new(SamlAuthenticationEdgeTests.ClientId, completed.Result!.Code, Verifier))).Status);
        Assert.False(store.Redeemed);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HandoffRemainsBoundToImmutableProviderAndProtocol(bool replaceProvider)
    {
        var store = Store();
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        var started = await edge.BeginAsync(Start());
        var completed = await edge.CompleteExternalAsync(new(started.Result!.RelayState, Assertion(started.Result.RequestId)));
        if (replaceProvider) store.ProviderId = Guid.NewGuid();
        else store.Protocol = FederationProtocol.Saml;
        Assert.False((await services.GetRequiredService<FederationHandoffService>().RedeemAsync(new(SamlAuthenticationEdgeTests.ClientId, completed.Result!.Code, Verifier))).Status);
        Assert.False(store.Redeemed);
    }

    private TestFederationDal Store() => new()
    {
        RedirectAllowed = true, Protocol = FederationProtocol.SignedCallback,
        Configuration = JsonSerializer.Serialize(new
        {
            authorizationUrl = "https://corporate.example/login", callbackUrl = "https://auth.example/identity/federation/external/callback",
            audience = "identity-bridge", keys = new[] { new { id = "corporate-2026", pem = key.ExportSubjectPublicKeyInfoPem() } }
        })
    };
    private static BeginFederationRequest Start() => new(SamlAuthenticationEdgeTests.ClientId, "product-api", "corporate",
        SamlAuthenticationEdgeTests.Callback, "application-browser-state-123456", Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier))));
    private string Assertion(Guid attempt, string? fault = null)
    {
        using var other = RSA.Create(2048);
        SecurityKey signing = fault == "algorithm" ? new SymmetricSecurityKey(new byte[64]) : new RsaSecurityKey(fault == "signature" ? other : key);
        signing.KeyId = fault == "key" ? "unknown" : "corporate-2026";
        var header = new JwtHeader(new SigningCredentials(signing, fault == "algorithm" ? SecurityAlgorithms.HmacSha256 : SecurityAlgorithms.RsaSha256))
            { ["typ"] = fault == "type" ? "JWT" : "identity-bridge+jwt" };
        var payload = new JwtPayload
        {
            ["iss"] = fault == "issuer" ? "https://wrong.example" : "https://idp.example/issuer", ["sub"] = "employee-42",
            ["aud"] = fault == "audience" ? "other-service" : "identity-bridge", ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = Now.AddSeconds(fault == "expired" ? -1 : fault == "lifetime" ? 600 : 60).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"), ["attempt"] = (fault == "attempt" ? Guid.NewGuid() : attempt).ToString("N"),
            ["email"] = "employee@example.com", ["email_verified"] = true, ["name"] = "Employee"
        };
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }
    public void Dispose() => key.Dispose();
}
