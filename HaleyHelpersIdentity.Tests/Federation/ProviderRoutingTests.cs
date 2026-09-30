using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Haley.Abstractions;
using Haley.Constants;
using Haley.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Haley.Tests;

public sealed class ProviderRoutingTests
{
    private static Guid ApplicationId => SamlAuthenticationEdgeTests.ClientId;
    private static BeginFederationRequest Start(string email = "") => new(ApplicationId, "product-api", ReturnUri: SamlAuthenticationEdgeTests.Callback,
        State: "browser-bound-login-state-123456", CodeChallenge: Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(new string('a', 64)))), EmailOrDomain: email);

    [Theory]
    [InlineData("user@EXAMPLE.com")]
    [InlineData("example.com")]
    public async Task DomainStartsMatchingProviderWithoutExplicitCode(string email)
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        using var services = FederationTestServices.Create(store);
        var started = await services.GetRequiredService<IFederationAuthenticationService>().BeginAsync(Start(email));
        Assert.True(started.Status);
        Assert.Equal(7, store.CreatedRequest!.LocalProviderId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("user@unmatched.example")]
    public async Task ApplicationDefaultHandlesEmptyOrUnmatchedDomain(string email)
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        store.Configuration = WithPolicy(store.Configuration, defaults: [ApplicationId]);
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        Assert.True(Assert.Single((await edge.DiscoverAsync(new(email, ApplicationId, "product-api"))).Result!).IsDefault);
        Assert.True((await edge.BeginAsync(Start(email))).Status);
    }

    [Fact]
    public async Task DomainMatchTakesPrecedenceOverAnotherDefault()
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        var other = (await store.FindProviderAsync("corporate", default))! with { LocalProviderId = 8, ProviderId = Guid.NewGuid(), Code = "other", DiscoveryDomains = new[] { "other.example" } };
        store.AdditionalProviders.Add(other with { Configuration = WithPolicy(other.Configuration, defaults: [ApplicationId]) });
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        Assert.Equal("corporate", Assert.Single((await edge.DiscoverAsync(new("user@example.com", ApplicationId, "product-api"))).Result!).Code);
        Assert.True((await edge.BeginAsync(Start("user@example.com"))).Status);
        Assert.Equal(7, store.CreatedRequest!.LocalProviderId);
    }

    [Fact]
    public async Task AmbiguousDomainRequiresChoiceAndDoesNotCreateAttempt()
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        store.AdditionalProviders.Add((await store.FindProviderAsync("corporate", default))! with { LocalProviderId = 8, ProviderId = Guid.NewGuid(), Code = "other" });
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        Assert.Equal(2, (await edge.DiscoverAsync(new("example.com", ApplicationId, "product-api"))).Result!.Count);
        Assert.Equal(IdentityErrorCodes.FederationProviderSelectionRequired, (await edge.BeginAsync(Start("example.com"))).Key);
        Assert.Null(store.CreatedRequest);
        Assert.True((await edge.BeginAsync(Start("example.com") with { ProviderCode = "other" })).Status);
        Assert.Equal(8, store.CreatedRequest!.LocalProviderId);
    }

    [Fact]
    public async Task DuplicateDefaultsFailClosedEvenIfWrittenConcurrently()
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        store.Configuration = WithPolicy(store.Configuration, defaults: [ApplicationId]);
        store.AdditionalProviders.Add((await store.FindProviderAsync("corporate", default))! with { LocalProviderId = 8, ProviderId = Guid.NewGuid(), Code = "other" });
        using var services = FederationTestServices.Create(store);
        Assert.Equal(IdentityErrorCodes.FederationDefaultConflict, (await services.GetRequiredService<IFederationAuthenticationService>().BeginAsync(Start())).Key);
        Assert.Null(store.CreatedRequest);
    }

    [Theory]
    [InlineData("restricted")]
    [InlineData("retired")]
    [InlineData("tenant-allowlist")]
    [InlineData("invalid-default")]
    public async Task DiscoveryAndAutomaticStartNeverOfferDisallowedProvider(string condition)
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        if (condition == "restricted") store.Configuration = WithPolicy(store.Configuration, allowed: [Guid.NewGuid()]);
        if (condition == "retired") store.ProviderStatus = IdentityRecordStatus.Retired;
        if (condition == "tenant-allowlist") store.RequireApplicationAllowlist = true;
        if (condition == "invalid-default") store.Configuration = WithPolicy(store.Configuration, allowed: [Guid.NewGuid()], defaults: [ApplicationId]);
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        Assert.Empty((await edge.DiscoverAsync(new("example.com", ApplicationId, "product-api"))).Result!);
        Assert.Equal(IdentityErrorCodes.FederationProviderNotFound, (await edge.BeginAsync(Start("example.com"))).Key);
        Assert.False((await edge.BeginAsync(Start("example.com") with { ProviderCode = "corporate" })).Status);
        Assert.Null(store.CreatedRequest);
    }

    [Fact]
    public async Task ResourceAuthorityIsCheckedBeforeDiscoveryOrStart()
    {
        var store = new TestFederationDal { RedirectAllowed = true, ResourceAllowed = false };
        using var services = FederationTestServices.Create(store);
        var edge = services.GetRequiredService<IFederationAuthenticationService>();
        Assert.Equal(IdentityErrorCodes.InvalidClientResource, (await edge.DiscoverAsync(new("example.com", ApplicationId, "product-api"))).Key);
        Assert.False((await edge.BeginAsync(Start("example.com"))).Status);
        Assert.Null(store.CreatedRequest);
    }

    [Fact]
    public async Task ExplicitProviderStillRequiresRegisteredReturnAddress()
    {
        var store = new TestFederationDal();
        using var services = FederationTestServices.Create(store);
        var result = await services.GetRequiredService<IFederationAuthenticationService>().BeginAsync(Start() with { ProviderCode = "corporate" });
        Assert.Equal(IdentityErrorCodes.InvalidClientResource, result.Key);
        Assert.Null(store.CreatedRequest);
    }

    [Theory]
    [InlineData("@example.com")]
    [InlineData("a@@example.com")]
    [InlineData("not a domain")]
    public async Task InvalidHintDoesNotFallBackToDefault(string email)
    {
        var store = new TestFederationDal { RedirectAllowed = true };
        store.Configuration = WithPolicy(store.Configuration, defaults: [ApplicationId]);
        using var services = FederationTestServices.Create(store);
        var result = await services.GetRequiredService<IFederationAuthenticationService>().BeginAsync(Start(email));
        Assert.Equal(IdentityErrorCodes.InvalidRequest, result.Key);
        Assert.Null(store.CreatedRequest);
    }

    internal static string WithPolicy(string configuration, Guid[]? allowed = null, Guid[]? defaults = null)
    {
        var json = JsonNode.Parse(configuration)!.AsObject();
        if (allowed is not null) json["allowedApplicationIds"] = new JsonArray(allowed.Select(id => JsonValue.Create(id.ToString("D"))).ToArray());
        if (defaults is not null) json["defaultForApplicationIds"] = new JsonArray(defaults.Select(id => JsonValue.Create(id.ToString("D"))).ToArray());
        return json.ToJsonString();
    }
}
