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
            database.Services.GetRequiredService<IOptions<IdentityServerOptions>>().Value.TotpLogin.Enabled = true;
            var enrollment = await remote.BeginTotpEnrollmentAsync(new(account.Result.UserId, "Password-free HTTP account"));
            Assert.True(enrollment.Status, enrollment.Message);
            var details = await remote.InspectTotpEnrollmentAsync(enrollment.Result.Ticket);
            var seed = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(details.Result.OtpauthUri).Query)["secret"].ToString();
            Assert.True((await remote.ConfirmTotpEnrollmentAsync(new(enrollment.Result.Ticket, MfaPersistenceTests.Code(seed, database.Clock.UtcNow)))).Status);
            database.Clock.UtcNow = database.Clock.UtcNow.AddSeconds(30);
            var totp = await remote.AuthenticateTotpAsync(new("http@example.test", MfaPersistenceTests.Code(seed, database.Clock.UtcNow)));
            Assert.True(totp.Status, totp.Message); Assert.True((await remote.ValidateSessionAsync(totp.Result.Token)).Status);
            Assert.Equal("[\"totp\"]", await database.SqlAsync("SELECT i.auth_methods FROM user_session_info i JOIN user_session s ON s.id=i.session_id WHERE s.uid=@uid",
                ("@uid", Convert.FromHexString(totp.Result.SessionId.ToString("N")))));
            Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM credential")));
        }
        finally { ClientStore.RemoveClient(key); }
    }
}
