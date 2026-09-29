using System.Net;
using System.Net.Http.Json;
using Haley.Extensions;
using Haley.Hosting;
using Haley.Models;
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
        var app = builder.Build();
        IdentityHosting.ConfigureErrors(app);
        app.UseAuthentication(); app.UseAuthorization(); app.UseAntiforgery(); app.UseRateLimiter();
        app.MapIdentityManagementSessions();
        app.MapMethods("/admin/api/probe", ["GET", "POST"], () => Results.NoContent())
            .RequireAuthorization(IdentityManagementHosting.Policy).AddEndpointFilter<UnsafeMethodAntiforgeryFilter>();
        return app;
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
