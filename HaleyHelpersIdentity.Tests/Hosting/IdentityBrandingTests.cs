using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Haley.Extensions;
using Haley.Models;
using Haley.Security;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class IdentityBrandingTests
{
    [Theory]
    [InlineData(null, "Haley Identity")]
    [InlineData("", "Haley Identity")]
    [InlineData("   ", "Haley Identity")]
    [InlineData("  Learn Desk  ", "Learn Desk")]
    [InlineData("EPBIM / Identity", "EPBIM / Identity")]
    public async Task HostNameIsSharedByAuthenticatorUriAndAnonymousConsoleBootstrap(string? configured, string expected)
    {
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { [$"{IdentityServerOptions.SectionName}:IssuerLabel"] = configured });
        builder.Services.Configure<IdentityServerOptions>(builder.Configuration.GetSection(IdentityServerOptions.SectionName));
        builder.Services.Configure<IdentityManagementOptions>(options => options.Enabled = false);
        builder.Services.AddSingleton(services => new ManagementSessionService(
            services.GetRequiredService<IOptionsMonitor<IdentityManagementOptions>>(), null!, TimeProvider.System));
        builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        builder.Services.AddAuthentication().AddCookie(); builder.Services.AddAuthorization(); builder.Services.AddAntiforgery();
        await using var app = builder.Build(); app.MapIdentityManagementSessions(); await app.StartAsync();
        var options = app.Services.GetRequiredService<IOptions<IdentityServerOptions>>();
        var clock = new TestClock(); var uuids = new Uuid7Generator(clock); var methodId = Guid.NewGuid();
        var protector = new AesGcmSecretProtector([new SecretProtectionKey("test", RandomNumberGenerator.GetBytes(32), true)]);
        var seed = RandomNumberGenerator.GetBytes(20);
        try
        {
            var method = new StoredMfaMethod(new(methodId, Guid.NewGuid(), MfaKind.Totp, "user@example.test",
                IdentityRecordStatus.Pending, clock.UtcNow, null, null),
                protector.Protect(seed, $"{options.Value.MfaProtectionPurpose}:{methodId:N}"), null);
            var store = new TotpLoginStore { Enrollment = new(method, 0, 5, clock.UtcNow.AddMinutes(5), null, null, null) };
            var service = new MfaService(store, protector, new SecretTokenGenerator(), uuids, clock, options);
            var details = await service.InspectTotpEnrollmentAsync("test-enrollment-ticket");
            Assert.True(details.Status, details.Message);
            var uri = new Uri(details.Result.OtpauthUri);
            Assert.Equal(expected, QueryHelpers.ParseQuery(uri.Query)["issuer"].ToString());
            Assert.Equal(expected + ":user@example.test", Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/')));
            Assert.Equal("user@example.test", details.Result.AccountLabel);
            using var client = app.GetTestClient(); using var response = await client.GetAsync("/admin/api/session");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var session = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(expected, session.RootElement.GetProperty("identityName").GetString());
            Assert.False(session.RootElement.GetProperty("authenticated").GetBoolean());
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
}
