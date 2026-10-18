using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Extensions;
using Haley.Hosting;
using Haley.Models;
using Haley.Services;
using Haley.Security;
using Haley.Utils;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class WorkflowManagementTests
{
    private static readonly Guid ApplicationId = Guid.Parse("20386153-b9d6-489c-bd94-43c780ad8ea9");
    private static readonly Guid UserId = Guid.Parse("2938b928-bc6c-4e8a-bb51-41c93b57c9aa");
    [Theory]
    [InlineData(VerificationPurpose.EmailVerification, VerificationProofKind.NumericCode)]
    [InlineData(VerificationPurpose.EmailVerification, VerificationProofKind.OpaqueToken)]
    [InlineData(VerificationPurpose.PasswordReset, VerificationProofKind.NumericCode)]
    [InlineData(VerificationPurpose.PasswordReset, VerificationProofKind.OpaqueToken)]
    [InlineData(VerificationPurpose.PasswordlessLogin, VerificationProofKind.NumericCode)]
    [InlineData(VerificationPurpose.PasswordlessLogin, VerificationProofKind.OpaqueToken)]
    public async Task ConsoleCanIssueCodesAndLinksForAnAlreadyVerifiedAccount(VerificationPurpose purpose, VerificationProofKind kind)
    {
        var store = new Haley.Tests.HostedVerificationStore(); var clock = new TestClock();
        store.Subject = store.Subject with { Identity = store.Subject.Identity with { Status = IdentityStatus.Active },
            VerifiedAt = clock.UtcNow, RecoveryEnabled = true, CredentialId = Guid.NewGuid() };
        var options = Options.Create(new IdentityServerOptions { PasswordHashIterations = 100000 });
        var tokens = new SecretTokenGenerator(); var uuids = new Uuid7Generator(clock); var hasher = new Pbkdf2PasswordHasher(options);
        var service = new IdentityVerificationService(store, new VerificationProofService(hasher, tokens, uuids, clock, options),
            new TestApplicationContext(), new TotpLoginAuthorization(), new Haley.Tests.HostedVerificationMfaPolicy(),
            hasher, tokens, uuids, clock, options);
        await using var app = CreateApplication(out _, service, store); app.MapIdentityVerificationManagement();
        await app.StartAsync(); using var client = app.GetTestClient(); await AuthorizeAsync(client);
        using var result = await client.PostAsJsonAsync("/admin/api/verification/challenges",
            new { ApplicationId, Request = new BeginIdentityVerificationRequest(store.Subject.Email, purpose, kind),
                PageUrl = "https://identity.example.test/identity/verify/" });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        using var body = JsonDocument.Parse(await result.Content.ReadAsStringAsync());
        Assert.Equal((int)purpose, body.RootElement.GetProperty("delivery").GetProperty("purpose").GetInt32());
        Assert.Contains("#proof=", body.RootElement.GetProperty("link").GetString());
        Assert.NotNull(store.Challenge);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmailOwnershipChangesRequireOperatorAuthenticationAndAntiforgery(bool authenticated)
    {
        await using var app = CreateApplication(out _); app.MapIdentityVerificationManagement();
        await app.StartAsync(); using var client = app.GetTestClient();
        if (authenticated) client.DefaultRequestHeaders.Add("X-Test-Operator", "yes");
        using var result = await client.PutAsJsonAsync(
            $"/admin/api/verification/accounts/{UserId:D}/email-contacts/{Guid.NewGuid():D}/verification",
            new AdminEmailVerificationAction(true, "operator_review"));
        Assert.Equal(authenticated ? HttpStatusCode.BadRequest : HttpStatusCode.Unauthorized, result.StatusCode);
    }
    [Fact]
    public async Task FullEmailContactsCannotBeReadWithoutTheOperatorSession()
    {
        await using var app = CreateApplication(out _);
        app.MapIdentityVerificationManagement();
        await app.StartAsync(); using var client = app.GetTestClient();
        using var result = await client.GetAsync($"/admin/api/verification/accounts/{UserId:D}/email-contacts");
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
    }

    [Fact]
    public async Task WorkflowRequiresOperatorAuthentication()
    {
        await using var app = CreateApplication(out var probe);
        await app.StartAsync(); using var client = app.GetTestClient();
        using var result = await client.PostAsJsonAsync(SessionPath(ApplicationId), new PasswordAuthenticationRequest("user@example.test", "test-password"));
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode); Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task WorkflowRequiresAntiforgeryEvenForAuthenticatedOperator()
    {
        await using var app = CreateApplication(out var probe);
        await app.StartAsync(); using var client = app.GetTestClient(); client.DefaultRequestHeaders.Add("X-Test-Operator", "yes");
        using var result = await client.PostAsJsonAsync(SessionPath(ApplicationId), new PasswordAuthenticationRequest("user@example.test", "test-password"));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode); Assert.Equal(0, probe.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OnlyRegisteredApplicationCanBeSelected(bool registered)
    {
        await using var app = CreateApplication(out var probe);
        await app.StartAsync(); using var client = app.GetTestClient(); await AuthorizeAsync(client);
        var id = registered ? ApplicationId : Guid.NewGuid();
        using var result = await client.PostAsJsonAsync(SessionPath(id), new PasswordAuthenticationRequest("user@example.test", "test-password"));
        Assert.Equal(registered ? HttpStatusCode.OK : HttpStatusCode.Forbidden, result.StatusCode);
        Assert.Equal(registered ? 1 : 0, probe.Calls);
        if (registered) Assert.Equal(ApplicationId.ToString("D"), probe.ApplicationHeader);
    }

    [Fact]
    public async Task FullProfileSupportsUuidAccountsAndAllFields()
    {
        await using var app = CreateApplication(out var probe);
        await app.StartAsync(); using var client = app.GetTestClient(); await AuthorizeAsync(client);
        using var account = await client.GetAsync($"/admin/api/users/{UserId:D}");
        Assert.Equal(HttpStatusCode.OK, account.StatusCode); Assert.Contains("username-only", await account.Content.ReadAsStringAsync());
        var request = new UpdateUserProfileRequest("Updated", "Given", "Family", "Preferred", "en-AE", "Asia/Dubai", "https://example.test/avatar.png");
        using var profile = await client.PutAsJsonAsync($"/admin/api/users/{UserId:D}/profile", request);
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode); Assert.Equal(request, probe.LastRequest);
        Assert.True(profile.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task RecoveryCodeReplacementRejectsDifferentBodyUser()
    {
        await using var app = CreateApplication(out var probe);
        await app.StartAsync(); using var client = app.GetTestClient(); await AuthorizeAsync(client);
        using var result = await client.PostAsJsonAsync($"/admin/api/users/{UserId:D}/mfa/recovery-codes", new ReplaceRecoveryCodesRequest(Guid.NewGuid(), 10));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode); Assert.Equal(0, probe.Calls);
    }

    private static string SessionPath(Guid id) => $"/admin/api/identity/workflows/{id:D}/haley.identity/sessions/password";
    private static WebApplication CreateApplication(out WorkflowAccountProxy probe, IdentityVerificationService? verification = null,
        IIdentityVerificationStore? verificationStore = null)
    {
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
        builder.Services.AddAuthentication("Workflow.Test").AddScheme<AuthenticationSchemeOptions, WorkflowOperatorAuthentication>("Workflow.Test", _ => { });
        builder.Services.AddAuthorization(options => options.AddPolicy(IdentityManagementHosting.Policy, policy => policy.RequireAuthenticatedUser().RequireClaim(IdentityManagementHosting.SessionClaim)));
        builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN"); builder.Services.AddHttpContextAccessor();
        // No persistence dependency may be used before the management/antiforgery boundary succeeds.
        builder.Services.AddScoped(_ => new IdentityAdministrationService(null!, null!, null!, null!, null!, null!));
        builder.Services.AddScoped<IdentityVerificationService>(_ => verification ?? throw new InvalidOperationException("The authorization test must not generate challenges."));
        builder.Services.AddSingleton<IIdentityVerificationStore>(verificationStore ?? new Haley.Tests.HostedVerificationStore());
        builder.Services.AddSingleton(new IdentityApplicationRegistry(new() { [ApplicationId.ToString("D")] = new() { ["test-key"] = "test-application-binding-secret-with-32-characters" } }));
        var identity = DispatchProxy.Create<IIdentity, WorkflowAccountProxy>(); probe = (WorkflowAccountProxy)(object)identity;
        var captured = probe; builder.Services.AddScoped<IIdentity>(services => { captured.Accessor = services.GetRequiredService<IHttpContextAccessor>(); return identity; });
        var app = builder.Build(); IdentityHosting.ConfigureErrors(app);
        app.UseAuthentication(); app.UseAuthorization(); app.UseAntiforgery();
        app.MapGet("/test/token", (HttpContext context, IAntiforgery antiforgery) => Results.Json(antiforgery.GetAndStoreTokens(context).RequestToken)).AllowAnonymous();
        app.MapIdentityWorkflowManagement(); return app;
    }
    private static async Task AuthorizeAsync(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-Test-Operator", "yes"); using var result = await client.GetAsync("/test/token");
        var token = JsonSerializer.Deserialize<string>(await result.Content.ReadAsStringAsync());
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token);
        client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", result.Headers.GetValues("Set-Cookie").Select(value => value.Split(';')[0])));
    }
}
