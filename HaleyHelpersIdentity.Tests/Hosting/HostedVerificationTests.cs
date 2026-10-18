using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Extensions;
using Haley.Models;
using Haley.Security;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Tests;

public sealed class HostedVerificationTests
{
    [Fact]
    public async Task ApplicationHostedPageUsesItsExistingClientAndRejectsOtherApplicationContexts()
    {
        var application = Guid.NewGuid();
        var identity = System.Reflection.DispatchProxy.Create<IIdentity, RecipientIdentityProxy>();
        var recorder = (RecipientIdentityProxy)(object)identity;
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(identity); builder.Services.AddAdminLoginRateLimit("verification", 30);
        await using var app = builder.Build(); app.UseRateLimiter();
        app.MapIdentityVerificationProxyEndpoints(application, "product-api", "verification"); await app.StartAsync();
        using var client = app.GetTestClient();
        var proof = new CompleteIdentityVerificationRequest(Guid.NewGuid(), VerificationPurpose.EmailVerification, "opaque-proof");
        using var page = await client.GetAsync("/identity/verify/"); Assert.Equal(HttpStatusCode.OK, page.StatusCode); Assert.Equal(0, recorder.Calls);
        using var foreign = await client.PostAsJsonAsync($"/identity/verify/{Guid.NewGuid():D}/product-api/completion", proof);
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode); Assert.Equal(0, recorder.Calls);
        using var wrongResource = await client.PostAsJsonAsync($"/identity/verify/{application:D}/other-api/completion", proof);
        Assert.Equal(HttpStatusCode.Forbidden, wrongResource.StatusCode); Assert.Equal(0, recorder.Calls);
        using var valid = await client.PostAsJsonAsync($"/identity/verify/{application:D}/product-api/completion", proof);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode); Assert.Equal(1, recorder.Calls); Assert.Equal(proof, recorder.Submission);
        using var generation = await client.PostAsJsonAsync("/identity/verify/challenges", new { email = "recipient@example.test" });
        Assert.Equal(HttpStatusCode.NotFound, generation.StatusCode);
    }

    [Theory]
    [InlineData(VerificationProofKind.OpaqueToken)]
    [InlineData(VerificationProofKind.NumericCode)]
    public async Task RecipientPageUsesTheSameProofAndDoesNotConsumeItOnGet(VerificationProofKind kind)
    {
        var store = new HostedVerificationStore(); var clock = new Haley.Identity.Tests.TestClock();
        var authorization = new Haley.Identity.Tests.TotpLoginAuthorization();
        var options = Options.Create(new IdentityServerOptions { PasswordHashIterations = 100000 });
        var tokens = new SecretTokenGenerator(); var uuids = new Uuid7Generator(clock); var hasher = new Pbkdf2PasswordHasher(options);
        var application = Guid.NewGuid();
        var service = new IdentityVerificationService(store, new VerificationProofService(hasher, tokens, uuids, clock, options),
            new Haley.Identity.Tests.TestApplicationContext(), authorization, new HostedVerificationMfaPolicy(), hasher, tokens, uuids, clock, options);
        var issued = await service.BeginForApplicationAsync(application, "haley.identity", new(store.Subject.Email,
            VerificationPurpose.EmailVerification, kind, 300, "bound-state"));
        Assert.True(issued.Status); var delivery = issued.Result.Delivery!;
        var link = new Uri(IdentityVerificationLinks.Create("https://public.example/identity/verify/", application,
            "haley.identity", delivery, "bound-state"));
        Assert.Equal("", link.Query); Assert.DoesNotContain(delivery.Verifier, link.PathAndQuery);
        var metadata = JsonDocument.Parse(Uri.UnescapeDataString(link.Fragment["#proof=".Length..]));
        Assert.Equal((int)kind, metadata.RootElement.GetProperty("proofKind").GetInt32());
        Assert.Equal(kind == VerificationProofKind.OpaqueToken, metadata.RootElement.TryGetProperty("verifier", out _));

        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(service);
        builder.Services.AddSingleton(System.Reflection.DispatchProxy.Create<IIdentity, RecipientIdentityProxy>());
        builder.Services.AddAdminLoginRateLimit("verification", 30);
        builder.Services.AddAdminLoginRateLimit("Haley.Identity", 30);
        await using var app = builder.Build(); app.UseRateLimiter();
        app.MapIdentityVerificationBrowserEndpoints(rateLimitPolicy: "verification");
        app.MapHaleyIdentityEndpoints(configure: endpointOptions => endpointOptions.Standalone = false);
        await app.StartAsync();
        using var client = app.GetTestClient();
        using var page = await client.GetAsync("/identity/verify/"); Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync(); Assert.Contains("./verification.js", html); Assert.DoesNotContain("kida-admin.config", html);
        Assert.Equal(0, store.Reads); Assert.Equal(0, store.Completions);
        using var script = await client.GetAsync("/identity/verify/verification.js"); Assert.Equal(HttpStatusCode.OK, script.StatusCode);
        var submission = new CompleteIdentityVerificationRequest(delivery.ChallengeId, delivery.Purpose, delivery.Verifier, kind, "bound-state");
        using var wrongApplication = await client.PostAsJsonAsync($"/identity/verify/{Guid.NewGuid():D}/haley.identity/completion", submission);
        Assert.False(wrongApplication.IsSuccessStatusCode); Assert.Equal(0, store.Completions);
        using var wrongResource = await client.PostAsJsonAsync($"/identity/verify/{application:D}/other.resource/completion", submission);
        Assert.False(wrongResource.IsSuccessStatusCode); Assert.Equal(0, store.Completions);
        var inspection = new InspectIdentityVerificationRequest(delivery.ChallengeId,
            VerificationPurpose.EmailVerification, delivery.Verifier, kind, "bound-state");
        var inspected = await service.InspectForApplicationAsync(application, "haley.identity", inspection);
        Assert.Equal(kind == VerificationProofKind.OpaqueToken, inspected.Status);
        Assert.Equal(0, store.Completions);
        if (kind == VerificationProofKind.OpaqueToken)
        {
            for (var attempt = 0; attempt < 8; attempt++)
                Assert.False((await service.InspectForApplicationAsync(application, "haley.identity",
                    inspection with { Verifier = "invalid-link-proof" })).Status);
            Assert.True((await service.InspectForApplicationAsync(application, "haley.identity", inspection)).Status);
        }

        using var completed = await client.PostAsJsonAsync($"/api/identity/verification/recipient/{application:D}/haley.identity/completion", submission);
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode); Assert.Equal(1, store.Completions);
        Assert.False((await service.InspectForApplicationAsync(application, "haley.identity", inspection)).Status);
        Assert.Equal(IdentityStatus.Pending, store.Subject.Identity.Status); Assert.NotNull(store.Subject.VerifiedAt);
        using var replay = await client.PostAsJsonAsync($"/identity/verify/{application:D}/haley.identity/completion", submission);
        Assert.False(replay.IsSuccessStatusCode); Assert.Equal(1, store.Completions);

        var next = await service.BeginForApplicationAsync(application, "haley.identity", new(store.Subject.Email,
            VerificationPurpose.EmailVerification, kind, 60, "expiry-state"));
        clock.UtcNow = clock.UtcNow.AddSeconds(61);
        using var expired = await client.PostAsJsonAsync($"/identity/verify/{application:D}/haley.identity/completion",
            new CompleteIdentityVerificationRequest(next.Result.Delivery!.ChallengeId, VerificationPurpose.EmailVerification,
                next.Result.Delivery.Verifier, kind, "expiry-state"));
        Assert.False(expired.IsSuccessStatusCode); Assert.Equal(1, store.Completions);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://user:password@example.test/verify/")]
    [InlineData("https://example.test/verify/#existing")]
    public void LinkBuilderRejectsInvalidPageLocations(string page)
    {
        var delivery = new IdentityVerificationDelivery(Guid.NewGuid(), VerificationPurpose.EmailVerification,
            VerificationProofKind.OpaqueToken, "recipient@example.test", "test-verifier", DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow);
        Assert.Throws<ArgumentException>(() => IdentityVerificationLinks.Create(page, Guid.NewGuid(), "haley.identity", delivery));
    }

    [Fact]
    public async Task LockedAccountCannotRequestOrCompletePasswordlessLoginAndReceivesAnExplicitReason()
    {
        var store = new HostedVerificationStore();
        var clock = new Haley.Identity.Tests.TestClock();
        store.Subject = store.Subject with
        {
            VerifiedAt = clock.UtcNow,
            RecoveryEnabled = true,
            Identity = store.Subject.Identity with { Status = IdentityStatus.Active }
        };
        var options = Options.Create(new IdentityServerOptions { PasswordHashIterations = 100000 });
        var tokens = new SecretTokenGenerator();
        var uuids = new Uuid7Generator(clock);
        var hasher = new Pbkdf2PasswordHasher(options);
        var application = Guid.NewGuid();
        var service = new IdentityVerificationService(store,
            new VerificationProofService(hasher, tokens, uuids, clock, options),
            new Haley.Identity.Tests.TestApplicationContext(), new Haley.Identity.Tests.TotpLoginAuthorization(),
            new HostedVerificationMfaPolicy(), hasher, tokens, uuids, clock, options);
        var request = new BeginIdentityVerificationRequest(store.Subject.Email,
            VerificationPurpose.PasswordlessLogin, VerificationProofKind.NumericCode);
        var issued = await service.BeginForApplicationAsync(application, "haley.identity", request);
        Assert.True(issued.Status);
        var delivery = issued.Result.Delivery!;
        store.Subject = store.Subject with { Identity = store.Subject.Identity with { Status = IdentityStatus.Locked } };

        var blocked = await service.BeginForApplicationAsync(application, "haley.identity", request);
        var completion = await service.CompleteForApplicationAsync(application, "haley.identity",
            new(delivery.ChallengeId, delivery.Purpose, delivery.Verifier, delivery.ProofKind));

        Assert.False(blocked.Status);
        Assert.False(completion.Status);
        Assert.Equal("identity.account_locked", blocked.Key);
        Assert.Equal("identity.account_locked", completion.Key);
        Assert.Equal(423, blocked.Code);
        Assert.Equal(423, completion.Code);
        Assert.Equal(0, store.Completions);
        Assert.Equal(IdentityStatus.Locked, store.Subject.Identity.Status);
    }
}
