using Haley.Constants;
using Microsoft.Extensions.DependencyInjection;
using Haley.Models;
using Haley.Abstractions;
using Haley.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Haley.Tests;
public sealed class SamlAuthenticationEdgeTests
{
    internal static readonly Guid ClientId = Guid.Parse("11111111-1111-4111-8111-111111111111");
    internal static readonly Guid ProviderId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    internal static readonly Guid RequestId = Guid.Parse("33333333-3333-4333-8333-333333333333");
    internal static readonly DateTimeOffset Now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);
    internal const string Callback = "https://product.example/auth/kida/callback";
    private const string State = "product-login-state";
    private const string Verifier = "product-pkce-verifier-012345678901234567890";
    [Fact]
    public async Task BeginCreatesCorrelatedRequestForExactAllowedCallback()
    {
        var store = new TestFederationDal
        {
            RedirectAllowed = true
        };
        var service = CreateService(store);
        var result = await service.BeginAsync(new(ClientId, "product-api", "corporate", Callback, State, Challenge()));
        Assert.True(result.Status);
        Assert.NotNull(result.Result);
        Assert.Equal("https://idp.example/sso", result.Result.IdentityProviderUrl);
        Assert.Equal(RequestId, result.Result.RequestId);
        Assert.False(string.IsNullOrWhiteSpace(result.Result.SamlRequest));
        Assert.StartsWith("https://idp.example/sso?SAMLRequest=", result.Result.AuthorizationUrl, StringComparison.Ordinal);
        Assert.Equal(RequestId.ToString("N"), result.Result.RelayState);
        Assert.NotNull(store.CreatedRequest);
        Assert.Equal(ClientId, store.CreatedRequest.ApplicationId);
        Assert.Equal("product-api", store.CreatedRequest.Context);
        Assert.Equal(Callback, store.CreatedRequest.ReturnUri);
        Assert.Equal(State, store.CreatedRequest.State);
        Assert.Equal(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)), store.CreatedRequest.CodeChallenge);
        Assert.StartsWith("_", store.CreatedRequest.ProtocolRequestId, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BeginRejectsCallbackOutsideClientAllowlist()
    {
        var store = new TestFederationDal
        {
            RedirectAllowed = false
        };
        var service = CreateService(store);
        var result = await service.BeginAsync(new(ClientId, "product-api", "corporate", Callback, State, Challenge()));
        Assert.False(result.Status);
        Assert.Equal(IdentityErrorCodes.InvalidClientResource, result.Key);
        Assert.Null(store.CreatedRequest);
    }

    [Fact]
    public async Task BeginRejectsMissingBrowserBinding()
    {
        var store = new TestFederationDal
        {
            RedirectAllowed = true
        };
        var service = CreateService(store);
        var result = await service.BeginAsync(new(ClientId, "product-api", "corporate", Callback));
        Assert.False(result.Status);
        Assert.Equal(IdentityErrorCodes.InvalidRequest, result.Key);
        Assert.Null(store.CreatedRequest);
    }

    [Theory]
    [InlineData("validateSignature")]
    [InlineData("validateIssuer")]
    [InlineData("validateAudience")]
    [InlineData("validateLifetime")]
    [InlineData("validateDestination")]
    [InlineData("validateRecipient")]
    [InlineData("validateInResponseTo")]
    [InlineData("validateReplay")]
    public async Task ProviderCannotDisableAnyRequiredProofValidation(string validation)
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        var configuration = System.Text.Json.Nodes.JsonNode.Parse(store.Configuration)!;
        configuration["validation"] = new System.Text.Json.Nodes.JsonObject { [validation] = false };
        store.Configuration = configuration.ToJsonString();
        Assert.False((await CreateService(store).BeginAsync(new(ClientId, "product-api", "corporate", Callback, State, Challenge()))).Status);
        Assert.Null(store.CreatedRequest);
    }

    private static IFederationAuthenticationService CreateService(TestFederationDal store) =>
        FederationTestServices.Create(store).GetRequiredService<IFederationAuthenticationService>();
    private static string Challenge() => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
