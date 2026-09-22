using Haley.Abstractions;
using Haley.Models;
using Haley.Rest;
using Haley.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Microsoft.AspNetCore.Http;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class IdentityRemoteTests
{
    [Fact]
    public async Task RemoteClientPreservesBindingHeadersProblemDetailsAndCancellation()
    {
        var appId = Guid.NewGuid();
        using var server = new TestServer(new WebHostBuilder().Configure(app => app.Run(async context =>
        {
            Assert.Equal(appId.ToString("D"), context.Request.Headers["X-Haley-Application-Id"]);
            Assert.Equal("active", context.Request.Headers["X-Haley-Session-Key-Id"]);
            Assert.Equal("test-session-binding-secret-for-transport", context.Request.Headers["X-Haley-Session-Key"]);
            Assert.Equal("/api/identity/sessions/validation", context.Request.Path);
            context.Response.StatusCode = 400; context.Response.ContentType = "application/problem+json";
            await context.Response.WriteAsync("{\"detail\":\"Session token is malformed.\",\"code\":\"invalid_session\",\"traceId\":\"trace-test\"}");
        })));
        var options = Options.Create(new IdentityOptions { ApplicationId = appId, Url = "base=http://localhost/;", ApiPath = "api/identity",
            SessionKeyId = "active", SessionBindingSecret = "test-session-binding-secret-for-transport" });
        var key = $"{typeof(IdentityRemoteTransport).FullName}:{appId:D}:{options.Value.Url}";
        ClientStore.AddClient(key, new FluentClient("http://localhost/", server.CreateHandler()));
        try
        {
            var client = new IdentityRemoteClient(new(options, new IdentityRemoteAuthentication(), NullLogger<IdentityRemoteTransport>.Instance));
            var result = await client.ValidateSessionAsync("invalid");
            Assert.False(result.Status); Assert.Equal(400, result.Code); Assert.Equal("invalid_session", result.Key);
            Assert.Equal("Session token is malformed.", result.Message); Assert.Equal("trace-test", result.Trace);
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ValidateSessionAsync("invalid", cancelled.Token).AsTask());
        }
        finally { ClientStore.RemoveClient(key); }
    }
}
