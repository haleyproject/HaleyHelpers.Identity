using Haley.Abstractions;
using Haley.Extensions;
using Haley.Models;
using Haley.Rest;
using Haley.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class VerificationHttpTests
{
    [MariaDbFact]
    public async Task RemoteClientCanOnboardAndAuthenticateThroughTheRealEndpointMappings()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); var applicationId = Guid.NewGuid();
        using var scope = database.Scope(applicationId);
        var embedded = scope.ServiceProvider.GetRequiredService<IIdentity>();
        using var server = new TestServer(new WebHostBuilder().ConfigureServices(services =>
        {
            services.AddRouting(); services.Configure<Microsoft.AspNetCore.Routing.RouteHandlerOptions>(options => options.ThrowOnBadRequest = true); services.AddSingleton<IIdentity>(embedded); services.AddOptions<IdentityServerOptions>();
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapHaleyIdentityEndpoints(configure: options => options.Standalone = false));
        }));
        var settings = Options.Create(new IdentityOptions { ApplicationId = applicationId, Url = "base=http://localhost/;" });
        var key = $"{typeof(IdentityRemoteTransport).FullName}:{applicationId:D}:{settings.Value.Url}";
        ClientStore.AddClient(key, new FluentClient("http://localhost/", server.CreateHandler()));
        try
        {
            var remote = new IdentityRemoteClient(new(settings, new IdentityRemoteAuthentication(), NullLogger<IdentityRemoteTransport>.Instance));
            var account = await remote.EnsureAccountAsync(new("http@example.test", InitialStatus: IdentityStatus.Pending));
            Assert.True(account.Status, $"HTTP {account.Code}: {account.Message}"); Assert.Equal(IdentityStatus.Pending, account.Result.Status);
            var invitation = await remote.BeginVerificationAsync(new("http@example.test", VerificationPurpose.Onboarding, ValiditySeconds: 259200));
            Assert.True(invitation.Status, invitation.Message); Assert.NotNull(invitation.Result.Delivery);
            var delivery = invitation.Result.Delivery;
            var onboarded = await remote.CompleteVerificationAsync(new(delivery.ChallengeId, VerificationPurpose.Onboarding, delivery.Verifier));
            Assert.True(onboarded.Status, onboarded.Message); Assert.Equal(IdentityStatus.Active, onboarded.Result.AccountStatus);
            var email = await remote.GetEmailVerificationAsync("http@example.test"); Assert.True(email.Status, email.Message); Assert.True(email.Result.IsVerified);
            var begun = await remote.BeginVerificationAsync(new("http@example.test", VerificationPurpose.PasswordlessLogin, VerificationProofKind.NumericCode));
            Assert.True(begun.Status, begun.Message); Assert.NotNull(begun.Result.Delivery);
            var login = begun.Result.Delivery;
            var authenticated = await remote.CompleteVerificationAsync(new(login.ChallengeId, VerificationPurpose.PasswordlessLogin, login.Verifier, VerificationProofKind.NumericCode));
            Assert.True(authenticated.Status, authenticated.Message); Assert.NotNull(authenticated.Result.Session);
            Assert.True((await remote.ValidateSessionAsync(authenticated.Result.Session.Token)).Status);
        }
        finally { ClientStore.RemoveClient(key); }
    }
}
