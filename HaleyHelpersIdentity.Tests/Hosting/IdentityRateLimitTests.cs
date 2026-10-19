using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Extensions;
using Haley.Models;
using Haley.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Haley.Tests;

public sealed class IdentityRateLimitTests
{
    [Fact]
    public async Task OneHundredUsersCanEachReadTwiceFromOneIp()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        await using var app = await Host(identity, permitLimit: 2);
        using var client = Client(app);
        var users = Enumerable.Range(0, 100).Select(_ => Guid.NewGuid()).ToArray();
        foreach (var user in users)
            for (var read = 0; read < 2; read++)
                using (var response = await client.GetAsync($"/api/identity/accounts/{user:D}"))
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var repeated = await client.GetAsync($"/api/identity/accounts/{users[0]:D}");
        Assert.Equal(HttpStatusCode.TooManyRequests, repeated.StatusCode);
        Assert.NotNull(repeated.Headers.RetryAfter);
        using var problem = JsonDocument.Parse(await repeated.Content.ReadAsStringAsync());
        Assert.Equal("rate_limit_exceeded", problem.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task IpScopeIntentionallySharesTheAllowance()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        await using var app = await Host(identity, scope: "ip", permitLimit: 1);
        using var client = Client(app);
        using var first = await client.GetAsync($"/api/identity/accounts/{Guid.NewGuid():D}");
        using var second = await client.GetAsync($"/api/identity/accounts/{Guid.NewGuid():D}");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
    }

    [Fact]
    public async Task EmailAndAccountIdShareABudgetWithoutRepeatingTheLookup()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        var recorder = (RateLimitedIdentityProxy)(object)identity;
        var user = Guid.NewGuid();
        recorder.Accounts["alice@example.test"] = user;
        await using var app = await Host(identity, permitLimit: 1);
        using var client = Client(app);
        using var resolved = await client.PostAsJsonAsync("/api/identity/accounts/resolve", new AccountEmailRequest("Alice@EXAMPLE.test"));
        Assert.Equal(HttpStatusCode.OK, resolved.StatusCode);
        Assert.Equal(1, recorder.AccountLookups);
        using var read = await client.GetAsync($"/api/identity/accounts/{user:D}");
        Assert.Equal(HttpStatusCode.TooManyRequests, read.StatusCode);
    }

    [Fact]
    public async Task DifferentTokensForOneAccountShareItsBudgetAndValidationDoesNotExposeClaims()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        var recorder = (RateLimitedIdentityProxy)(object)identity;
        var user = Guid.NewGuid();
        recorder.Sessions["first-test-session"] = user;
        recorder.Sessions["second-test-session"] = user;
        await using var app = await Host(identity, permitLimit: 2);
        using var client = Client(app);
        foreach (var token in recorder.Sessions.Keys)
        {
            using var response = await client.PostAsJsonAsync("/api/identity/sessions/validation", new SessionTokenRequest(token));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(body.RootElement.TryGetProperty("userId", out _));
        }
        Assert.Equal(2, recorder.SessionResolutions);
        using var read = await client.GetAsync($"/api/identity/accounts/{user:D}");
        Assert.Equal(HttpStatusCode.TooManyRequests, read.StatusCode);
    }

    [Fact]
    public async Task ApplicationAuthenticationCannotBeBypassedWithAUserRoute()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        await using var app = await Host(identity, permitLimit: 1);
        using var client = app.GetTestClient();
        using var first = await client.GetAsync($"/api/identity/accounts/{Guid.NewGuid():D}");
        using var second = await client.GetAsync($"/api/identity/accounts/{Guid.NewGuid():D}");
        Assert.Equal(HttpStatusCode.BadRequest, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
    }

    [Fact]
    public async Task PendingVerificationChallengesAtOneIpHaveSeparateAllowances()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        await using var app = await Host(identity, permitLimit: 1);
        using var client = app.GetTestClient();
        var first = Guid.NewGuid();
        for (var i = 0; i < 100; i++)
        {
            var proof = new CompleteIdentityVerificationRequest(i == 0 ? first : Guid.NewGuid(),
                VerificationPurpose.EmailVerification, "test-proof");
            using var response = await client.PostAsJsonAsync("/test/proof", proof);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        using var repeat = await client.PostAsJsonAsync("/test/proof",
            new CompleteIdentityVerificationRequest(first, VerificationPurpose.EmailVerification, "test-proof"));
        Assert.Equal(HttpStatusCode.TooManyRequests, repeat.StatusCode);
    }

    [Fact]
    public async Task FederationAttemptsAtOneIpAreSeparatedAndTheFormRemainsReadable()
    {
        var identity = DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>();
        await using var app = await Host(identity, permitLimit: 1);
        using var client = app.GetTestClient();
        foreach (var attempt in new[] { "first-attempt", "second-attempt" })
        {
            using var response = await client.PostAsync("/test/federation",
                new FormUrlEncodedContent(new Dictionary<string, string> { ["RelayState"] = attempt }));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(attempt, await response.Content.ReadFromJsonAsync<string>());
        }
        using var repeat = await client.PostAsync("/test/federation",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["RelayState"] = "first-attempt" }));
        Assert.Equal(HttpStatusCode.TooManyRequests, repeat.StatusCode);
    }

    private static readonly Guid ApplicationId = Guid.NewGuid();
    private static readonly string BindingSecret = Guid.NewGuid().ToString("N");

    private static async Task<WebApplication> Host(IIdentity identity, string scope = "ip-user", int permitLimit = 2)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(identity);
        builder.Services.Configure<IdentityServerOptions>(options =>
        {
            options.TrustedNetwork = true;
            options.SessionBindingKeys[ApplicationId.ToString("D")] = new() { ["test"] = BindingSecret };
        });
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Limits:PermitLimit"] = permitLimit.ToString(),
            ["Limits:Scope"] = scope
        }).Build();
        builder.Services.AddConfiguredFixedWindowRateLimit("Haley.Identity", configuration.GetSection("Limits"));
        var app = builder.Build();
        app.UseRateLimiter();
        app.MapHaleyIdentityEndpoints();
        app.MapPost("/test/proof", (CompleteIdentityVerificationRequest request) => Results.Ok())
            .WithConfiguredFixedWindowRateLimit("Haley.Identity", Haley.Services.IdentityProofRateLimitSubject.ResolveAsync);
        app.MapPost("/test/federation", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync();
            return Results.Ok(form["RelayState"].ToString());
        })
            .WithConfiguredFixedWindowRateLimit("Haley.Identity", Haley.Services.IdentityProofRateLimitSubject.ResolveAsync);
        await app.StartAsync();
        return app;
    }

    private static HttpClient Client(WebApplication app)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Haley-Application-Id", ApplicationId.ToString("D"));
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key-Id", "test");
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key", BindingSecret);
        return client;
    }
}
