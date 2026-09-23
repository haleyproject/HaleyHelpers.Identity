using Haley.Models;
using Haley.Rest;
using Haley.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Text.Json;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class VerificationRemoteTests
{
    [Theory]
    [InlineData(VerificationPurpose.EmailVerification, "email")]
    [InlineData(VerificationPurpose.Onboarding, "onboarding")]
    [InlineData(VerificationPurpose.PasswordReset, "password-reset")]
    [InlineData(VerificationPurpose.PasswordlessLogin, "login")]
    public async Task RemoteVerificationUsesPurposeRoutesAndSendsSecretsOnlyInRequestBody(VerificationPurpose purpose, string segment)
    {
        var appId = Guid.NewGuid(); var challengeId = Guid.NewGuid(); var count = 0;
        using var server = new TestServer(new WebHostBuilder().Configure(app => app.Run(async context =>
        {
            Assert.Equal(appId.ToString("D"), context.Request.Headers["X-Haley-Application-Id"]);
            Assert.Equal("POST", context.Request.Method); Assert.False(context.Request.QueryString.HasValue);
            Assert.True(context.Request.HasJsonContentType());
            if (purpose == VerificationPurpose.PasswordlessLogin) Assert.Equal("active", context.Request.Headers["X-Haley-Session-Key-Id"]);
            using var body = await JsonDocument.ParseAsync(context.Request.Body);
            Assert.Equal((int)purpose, Property(body.RootElement, "purpose").GetInt32());
            context.Response.ContentType = "application/json";
            if (count++ == 0)
            {
                Assert.Equal($"/api/identity/verification/{segment}/challenges", context.Request.Path);
                Assert.Equal(259200, Property(body.RootElement, "validitySeconds").GetInt32());
                await context.Response.WriteAsJsonAsync(new IdentityVerificationInitiation(true));
            }
            else
            {
                Assert.Equal($"/api/identity/verification/{segment}/completion", context.Request.Path);
                Assert.Equal("one-time-secret", Property(body.RootElement, "verifier").GetString());
                Assert.Equal(challengeId, Property(body.RootElement, "challengeId").GetGuid());
                if (purpose == VerificationPurpose.PasswordlessLogin)
                    Assert.Equal((int)MfaKind.RecoveryCode, Property(body.RootElement, "mfaKind").GetInt32());
                await context.Response.WriteAsJsonAsync(new IdentityVerificationCompletion(Guid.NewGuid(), purpose, true, IdentityStatus.Active));
            }
        })));
        var options = Options.Create(new IdentityOptions { ApplicationId = appId, Url = "base=http://localhost/;", ApiPath = "api/identity",
            SessionKeyId = "active", SessionBindingSecret = "test-application-session-binding-secret" });
        var key = $"{typeof(IdentityRemoteTransport).FullName}:{appId:D}:{options.Value.Url}";
        ClientStore.AddClient(key, new FluentClient("http://localhost/", server.CreateHandler()));
        try
        {
            var authentication = new VerificationRemoteAuthentication();
            var client = new IdentityRemoteClient(new(options, authentication, NullLogger<IdentityRemoteTransport>.Instance));
            Assert.True((await client.BeginVerificationAsync(new("user@example.test", purpose, ValiditySeconds: 259200))).Status);
            Assert.True((await client.CompleteVerificationAsync(new(challengeId, purpose, "one-time-secret", MfaKind: purpose == VerificationPurpose.PasswordlessLogin ? MfaKind.RecoveryCode : null))).Status);
            Assert.Equal(new[] { "BeginVerification" + purpose, "CompleteVerification" + purpose }, authentication.Operations);
        }
        finally { ClientStore.RemoveClient(key); }
    }
    private static JsonElement Property(JsonElement body, string name) =>
        body.EnumerateObject().Single(property => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)).Value;
}
