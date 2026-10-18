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
using System.Text.Json.Serialization;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class VerificationRemoteTests
{
    [Fact]
    public async Task RemoteInspectionSendsProofInTheBodyAndReadsBooleanFeedback()
    {
        var appId = Guid.NewGuid();
        using var server = new TestServer(new WebHostBuilder().Configure(app => app.Run(async context =>
        {
            Assert.EndsWith("verification/onboarding/inspection", context.Request.Path.ToString());
            Assert.DoesNotContain("link-secret-proof", context.Request.QueryString.ToString());
            var request = await context.Request.ReadFromJsonAsync<InspectIdentityVerificationRequest>();
            Assert.NotNull(request);
            Assert.Equal("link-secret-proof", request.Verifier);
            Assert.Equal(VerificationPurpose.Onboarding, request.Purpose);
            Assert.Equal(VerificationProofKind.OpaqueToken, request.ProofKind);
            Assert.Equal("test-state", request.Context);
            await context.Response.WriteAsJsonAsync(true);
        })));
        var options = Options.Create(new IdentityOptions { ApplicationId = appId, Url = "base=http://localhost/;", ApiPath = "api/identity",
            SessionKeyId = "active", SessionBindingSecret = "test-application-session-binding-secret" });
        var key = $"{typeof(IdentityRemoteTransport).FullName}:{appId:D}:{options.Value.Url}";
        ClientStore.AddClient(key, new FluentClient("http://localhost/", server.CreateHandler()));
        try
        {
            var authentication = new VerificationRemoteAuthentication();
            var client = new IdentityRemoteClient(new(options, authentication, NullLogger<IdentityRemoteTransport>.Instance));
        var inspected = await client.InspectVerificationAsync(
            new(Guid.NewGuid(), VerificationPurpose.Onboarding, "link-secret-proof",
                VerificationProofKind.OpaqueToken, "test-state"));

        Assert.True(inspected.Status);
        Assert.True(inspected.Result);
        }
        finally { ClientStore.RemoveClient(key); }
    }


    [Fact]
    public async Task RecipientCompletionUsesOnlyTheBoundProofAndPreservesFeedback()
    {
        var application = Guid.NewGuid(); var calls = 0;
        using var server = new TestServer(new WebHostBuilder().Configure(app => app.Run(async context =>
        {
            calls++;
            Assert.Equal($"/api/identity/verification/recipient/{application:D}/haley.identity/completion", context.Request.Path);
            Assert.False(context.Request.QueryString.HasValue);
            Assert.False(context.Request.Headers.ContainsKey("Authorization"));
            Assert.False(context.Request.Headers.ContainsKey("X-Haley-Session-Key"));
            Assert.False(context.Request.Headers.ContainsKey("X-Haley-Application-Id"));
            using var body = await JsonDocument.ParseAsync(context.Request.Body);
            Assert.Equal("opaque-recipient-proof", body.RootElement.GetProperty("verifier").GetString());
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { detail = "The proof has expired.", code = "verification_invalid" });
        })));
        var options = Options.Create(new IdentityOptions { ApplicationId = application, Url = "base=http://localhost/;",
            SessionKeyId = "unused", SessionBindingSecret = "this-private-binding-secret-must-not-be-sent" });
        var key = $"{typeof(IdentityRemoteTransport).FullName}:{application:D}:{options.Value.Url}";
        ClientStore.AddClient(key, new FluentClient("http://localhost/", server.CreateHandler()));
        try
        {
            var transport = new IdentityRemoteTransport(options, new Haley.Tests.RejectingRecipientAuthentication(), NullLogger<IdentityRemoteTransport>.Instance);
            var submission = new CompleteIdentityVerificationRequest(Guid.NewGuid(), VerificationPurpose.EmailVerification, "opaque-recipient-proof");
            var result = await transport.CompleteRecipientAsync(application, "haley.identity", submission, default);
            Assert.False(result.Status); Assert.Equal("verification_invalid", result.Key); Assert.Equal("The proof has expired.", result.Message);
            var foreign = await transport.CompleteRecipientAsync(Guid.NewGuid(), "haley.identity", submission, default);
            Assert.Equal(403, foreign.Code); Assert.Equal(1, calls);
        }
        finally { ClientStore.RemoveClient(key); }
    }

    [Theory]
    [InlineData(VerificationPurpose.EmailVerification, "email", false)]
    [InlineData(VerificationPurpose.EmailVerification, "email", true)]
    [InlineData(VerificationPurpose.Onboarding, "onboarding", false)]
    [InlineData(VerificationPurpose.Onboarding, "onboarding", true)]
    [InlineData(VerificationPurpose.PasswordReset, "password-reset", false)]
    [InlineData(VerificationPurpose.PasswordReset, "password-reset", true)]
    [InlineData(VerificationPurpose.PasswordlessLogin, "login", false)]
    [InlineData(VerificationPurpose.PasswordlessLogin, "login", true)]
    public async Task RemoteVerificationUsesPurposeRoutesAndSendsSecretsOnlyInRequestBody(VerificationPurpose purpose, string segment, bool useStringEnums)
    {
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        if (useStringEnums) json.Converters.Add(new JsonStringEnumConverter());
        var proofKind = purpose is VerificationPurpose.Onboarding or VerificationPurpose.PasswordReset
            ? VerificationProofKind.OpaqueToken : VerificationProofKind.NumericCode;

        var appId = Guid.NewGuid(); var challengeId = Guid.NewGuid(); var count = 0;
        using var server = new TestServer(new WebHostBuilder().Configure(app => app.Run(async context =>
        {
            Assert.Equal(appId.ToString("D"), context.Request.Headers["X-Haley-Application-Id"]);
            Assert.Equal("POST", context.Request.Method); Assert.False(context.Request.QueryString.HasValue);
            Assert.True(context.Request.HasJsonContentType());
            Assert.Equal("active", context.Request.Headers["X-Haley-Session-Key-Id"]);
            Assert.Equal("test-application-session-binding-secret", context.Request.Headers["X-Haley-Session-Key"]);
            using var body = await JsonDocument.ParseAsync(context.Request.Body);
            Assert.Equal((int)purpose, Property(body.RootElement, "purpose").GetInt32());
            context.Response.ContentType = "application/json";
            if (count++ == 0)
            {
                Assert.Equal($"/api/identity/verification/{segment}/challenges", context.Request.Path);
                Assert.Equal(259200, Property(body.RootElement, "validitySeconds").GetInt32());
                await context.Response.WriteAsJsonAsync(new IdentityVerificationInitiation(true, new IdentityVerificationDelivery(
                    challengeId, purpose, proofKind, "person@example.test", "remote-test-verifier",
                    DateTimeOffset.UtcNow.AddMinutes(10), DateTimeOffset.UtcNow)), json);
            }
            else
            {
                Assert.Equal($"/api/identity/verification/{segment}/completion", context.Request.Path);
                Assert.Equal("one-time-secret", Property(body.RootElement, "verifier").GetString());
                Assert.Equal(challengeId, Property(body.RootElement, "challengeId").GetGuid());
                if (purpose == VerificationPurpose.PasswordlessLogin)
                    Assert.Equal((int)MfaKind.RecoveryCode, Property(body.RootElement, "mfaKind").GetInt32());
                await context.Response.WriteAsJsonAsync(new IdentityVerificationCompletion(Guid.NewGuid(), purpose, true, IdentityStatus.Active), json);
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
            var initiated = await client.BeginVerificationAsync(new("user@example.test", purpose, ValiditySeconds: 259200));
            Assert.True(initiated.Status);
            Assert.NotNull(initiated.Result?.Delivery);
            Assert.Equal(challengeId, initiated.Result!.Delivery!.ChallengeId);
            Assert.Equal(purpose, initiated.Result.Delivery.Purpose);
            Assert.Equal(proofKind, initiated.Result.Delivery.ProofKind);
            Assert.True((await client.CompleteVerificationAsync(new(challengeId, purpose, "one-time-secret", MfaKind: purpose == VerificationPurpose.PasswordlessLogin ? MfaKind.RecoveryCode : null))).Status);
            Assert.Equal(new[] { "BeginVerification" + purpose, "CompleteVerification" + purpose }, authentication.Operations);
        }
        finally { ClientStore.RemoveClient(key); }
    }
    private static JsonElement Property(JsonElement body, string name) =>
        body.EnumerateObject().Single(property => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)).Value;
}
