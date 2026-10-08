using System.Net;
using System.Net.Http.Json;
using Haley.Extensions;
using Haley.Hosting;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Haley.Tests;

public sealed class ManagementBoundaryTests
{
    [Fact]
    public async Task LoginRequiresAntiforgeryAndLogoutRevokesCopiedCookie()
    {
        var root = Path.Combine(Path.GetTempPath(), "identity-management-tests", Guid.NewGuid().ToString("N"));
        var time = new TestClock();
        await using var app = Build(root, time);
        await app.StartAsync();
        using var client = app.GetTestClient();
        var cookies = new Dictionary<string, string>();
        var anonymous = await Send(client, cookies, HttpMethod.Get, "/admin/api/session");
        var before = await anonymous.Content.ReadFromJsonAsync<AdminSessionResponse>();
        Assert.False(before!.Authenticated);
        Assert.True(before.PasswordConfigured);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(client, cookies, HttpMethod.Get, "/admin/api/probe")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(client, cookies, HttpMethod.Post, "/admin/api/login", body: new { password = "test-only-password" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Send(client, cookies, HttpMethod.Post, "/admin/api/login", before.AntiforgeryToken, new { password = "test-only-password" })).StatusCode);
        var after = await (await Send(client, cookies, HttpMethod.Get, "/admin/api/session")).Content.ReadFromJsonAsync<AdminSessionResponse>();
        Assert.True(after!.Authenticated);
        Assert.Equal(HttpStatusCode.NoContent, (await Send(client, cookies, HttpMethod.Post, "/admin/api/probe", after.AntiforgeryToken)).StatusCode);
        var stolenCopy = new Dictionary<string, string>(cookies);
        Assert.Equal(HttpStatusCode.NoContent, (await Send(client, cookies, HttpMethod.Post, "/admin/api/logout", after.AntiforgeryToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(client, stolenCopy, HttpMethod.Get, "/admin/api/probe")).StatusCode);
        await app.StopAsync();
        Directory.Delete(root, true);
    }

    [Fact]
    public async Task ManagementSessionExpiresOnServer()
    {
        var root = Path.Combine(Path.GetTempPath(), "identity-management-tests", Guid.NewGuid().ToString("N"));
        var time = new TestClock();
        await using var app = Build(root, time);
        await app.StartAsync();
        using var client = app.GetTestClient();
        var cookies = new Dictionary<string, string>();
        var session = await (await Send(client, cookies, HttpMethod.Get, "/admin/api/session")).Content.ReadFromJsonAsync<AdminSessionResponse>();
        await Send(client, cookies, HttpMethod.Post, "/admin/api/login", session!.AntiforgeryToken, new { password = "test-only-password" });
        Assert.Equal(HttpStatusCode.NoContent, (await Send(client, cookies, HttpMethod.Get, "/admin/api/probe")).StatusCode);
        time.Now = time.Now.AddHours(1);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(client, cookies, HttpMethod.Get, "/admin/api/probe")).StatusCode);
        await app.StopAsync();
        Directory.Delete(root, true);
    }

    private static WebApplication Build(string root, TimeProvider time)
    {
        Directory.CreateDirectory(root);
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{IdentityManagementOptions.SectionName}:PasswordHash"] = new PasswordHasher<object>().HashPassword(new(), "test-only-password"),
            [$"{IdentityManagementOptions.SectionName}:KeyDirectory"] = Path.Combine(root, "keys"),
            [$"{IdentityManagementOptions.SectionName}:LoginLockoutStatePath"] = Path.Combine(root, "lock.json")
        });
        builder.Services.AddSingleton(time);
        builder.AddIdentityManagement();
        builder.Services.AddSingleton(new IdentityApplicationRegistry(new(), Path.Combine(root, "appsettings.json")));
        builder.Services.Configure<IdentityServerOptions>(options => options.TrustedNetwork = true);
        builder.Services.AddHostedService<ApplicationRegistryReloadService>();
        var app = builder.Build();
        IdentityHosting.ConfigureErrors(app);
        app.UseAuthentication(); app.UseAuthorization(); app.UseAntiforgery(); app.UseRateLimiter();
        app.MapIdentityManagementSessions();
        app.MapIdentityApplicationManagement();
        app.MapGet("/api/identity/registry-probe", () => Results.Ok())
            .WithMetadata(new IdentityOperationMetadata("GetAccount", true)).AddEndpointFilter<IdentityBoundaryFilter>();
        app.MapMethods("/admin/api/probe", ["GET", "POST"], () => Results.NoContent())
            .RequireAuthorization(IdentityManagementHosting.Policy).AddEndpointFilter<UnsafeMethodAntiforgeryFilter>();
        return app;
    }

    [Fact]
    public async Task AdminCanRegisterRotateAndRevokeApplicationsWithoutExposingSecretsInLists()
    {
        var root = Path.Combine(Path.GetTempPath(), "identity-management-tests", Guid.NewGuid().ToString("N"));
        await using var app = Build(root, new TestClock());
        await app.StartAsync();
        using var admin = app.GetTestClient();
        using var caller = app.GetTestClient();
        var cookies = new Dictionary<string, string>();
        Assert.Equal(HttpStatusCode.Unauthorized, (await admin.GetAsync("/admin/api/applications")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        var anonymous = await (await Send(admin, cookies, HttpMethod.Get, "/admin/api/session")).Content.ReadFromJsonAsync<AdminSessionResponse>();
        await Send(admin, cookies, HttpMethod.Post, "/admin/api/login", anonymous!.AntiforgeryToken, new { password = "test-only-password" });
        var session = await (await Send(admin, cookies, HttpMethod.Get, "/admin/api/session")).Content.ReadFromJsonAsync<AdminSessionResponse>();
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(admin, cookies, HttpMethod.Post, "/admin/api/applications", body: new { displayName = "Test backend" })).StatusCode);
        var registered = await Send(admin, cookies, HttpMethod.Post, "/admin/api/applications", session!.AntiforgeryToken, new { displayName = "Test backend" });
        Assert.Equal(HttpStatusCode.OK, registered.StatusCode);
        Assert.True(registered.Headers.CacheControl?.NoStore);
        var original = (await registered.Content.ReadFromJsonAsync<IdentityApplicationCredential>())!;
        UseCredential(caller, original);
        Assert.Equal(HttpStatusCode.OK, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await caller.GetAsync("/admin/api/applications")).StatusCode);
        var list = await (await Send(admin, cookies, HttpMethod.Get, "/admin/api/applications")).Content.ReadAsStringAsync();
        Assert.DoesNotContain(original.SessionBindingSecret, list);
        Assert.DoesNotContain("sessionBindingSecret", list);
        var applicationPath = "/admin/api/applications/" + original.ApplicationId;
        var rotated = await Send(admin, cookies, HttpMethod.Post, applicationPath + "/keys", session.AntiforgeryToken);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var replacement = (await rotated.Content.ReadFromJsonAsync<IdentityApplicationCredential>())!;
        Assert.Equal(HttpStatusCode.OK, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Send(admin, cookies, HttpMethod.Delete, applicationPath + "/keys/" + original.SessionKeyId, session.AntiforgeryToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        UseCredential(caller, replacement);
        Assert.Equal(HttpStatusCode.OK, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(admin, cookies, HttpMethod.Delete, applicationPath)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Send(admin, cookies, HttpMethod.Delete, applicationPath, session.AntiforgeryToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        Assert.False(new IdentityApplicationRegistry(new(), Path.Combine(root, "appsettings.json"))
            .Authenticate(original.ApplicationId, replacement.SessionKeyId, replacement.SessionBindingSecret));
        await app.StopAsync();
        Directory.Delete(root, true);
    }

    [Fact]
    public async Task RunningHostDetectsExternalRegistryChangesWithoutRestarting()
    {
        var root = Path.Combine(Path.GetTempPath(), "identity-management-tests", Guid.NewGuid().ToString("N"));
        await using var app = Build(root, new TestClock());
        await app.StartAsync();
        using var caller = app.GetTestClient();
        var registryFile = Path.Combine(root, "appsettings.json");
        var console = new IdentityApplicationRegistry(new(), registryFile);
        var credential = (await console.RegisterAsync(new("Console registration"))).Result;
        UseCredential(caller, credential);
        await ExpectStatusEventually(caller, HttpStatusCode.OK);
        var valid = await File.ReadAllTextAsync(registryFile);
        await File.WriteAllTextAsync(registryFile, "{broken");
        await Task.Delay(1200);
        Assert.False(app.Lifetime.ApplicationStopping.IsCancellationRequested);
        Assert.Equal(HttpStatusCode.OK, (await caller.GetAsync("/api/identity/registry-probe")).StatusCode);
        await File.WriteAllTextAsync(registryFile, valid);
        Assert.True((await console.RevokeAsync(credential.ApplicationId)).Status);
        await ExpectStatusEventually(caller, HttpStatusCode.Unauthorized);
        await app.StopAsync();
        Directory.Delete(root, true);
    }

    private static void UseCredential(HttpClient client, IdentityApplicationCredential credential)
    {
        foreach (var name in new[] { "X-Haley-Application-Id", "X-Haley-Session-Key-Id", "X-Haley-Session-Key" }) client.DefaultRequestHeaders.Remove(name);
        client.DefaultRequestHeaders.Add("X-Haley-Application-Id", credential.ApplicationId.ToString("D"));
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key-Id", credential.SessionKeyId);
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key", credential.SessionBindingSecret);
    }

    private static async Task ExpectStatusEventually(HttpClient client, HttpStatusCode expected)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (true)
        {
            using var response = await client.GetAsync("/api/identity/registry-probe", timeout.Token);
            if (response.StatusCode == expected) return;
            await Task.Delay(50, timeout.Token);
        }
    }

    private static async Task<HttpResponseMessage> Send(HttpClient client, Dictionary<string, string> cookies, HttpMethod method,
        string path, string? csrf = null, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (cookies.Count > 0) request.Headers.Add("Cookie", string.Join("; ", cookies.Select(pair => pair.Key + "=" + pair.Value)));
        if (csrf is not null) request.Headers.Add("X-CSRF-TOKEN", csrf);
        if (body is not null) request.Content = JsonContent.Create(body);
        var response = await client.SendAsync(request);
        if (response.Headers.TryGetValues("Set-Cookie", out var values))
            foreach (var item in values)
            {
                var value = item.Split(';')[0]; var split = value.IndexOf('=');
                cookies[value[..split]] = value[(split + 1)..];
            }
        return response;
    }
    private sealed class TestClock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
