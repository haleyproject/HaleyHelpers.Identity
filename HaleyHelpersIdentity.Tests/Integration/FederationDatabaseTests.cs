using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class FederationDatabaseTests
{
    private const string Verifier = "real-database-pkce-verifier-with-at-least-forty-three-characters";
    private const string ReturnUri = "https://application.example/corporate/complete";

    [MariaDbFact]
    public async Task SignedProofPersistsAccountAndOnlyOneConcurrentRedemptionCreatesSession()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var key = RSA.Create(2048);
        var application = Guid.NewGuid();
        await Register(database, application, key, true);
        using var scope = database.Scope(application);
        var federation = scope.ServiceProvider.GetRequiredService<IIdentityFederation>();
        var candidates = await federation.DiscoverAsync(new(Context: "haley.identity"));
        Assert.True(candidates.Status, candidates.Message);
        Assert.True(Assert.Single(candidates.Result!).IsDefault);
        Assert.False((await federation.DiscoverAsync(new("example.com", Guid.NewGuid(), "haley.identity"))).Status);
        var attempt = await federation.BeginAsync(Start(application) with { ProviderCode = "", EmailOrDomain = "user@unmatched.example" });
        Assert.True(attempt.Status, attempt.Message);
        var completed = await federation.CompleteExternalAsync(new(attempt.Result!.RelayState,
            Sign(key, attempt.Result.RequestId, database.Clock.UtcNow), application));
        Assert.True(completed.Status, completed.Message);
        var redeem = new RedeemFederationHandoffRequest(application, completed.Result!.Code, Verifier);
        Assert.False((await federation.RedeemAsync(redeem with { CodeVerifier = new string('z', 64) })).Status);
        // Use separate request scopes, as real parallel requests do.
        using var otherScope = database.Scope(application);
        var results = await Task.WhenAll(federation.RedeemAsync(redeem).AsTask(),
            otherScope.ServiceProvider.GetRequiredService<IIdentityFederation>().RedeemAsync(redeem).AsTask());
        Assert.Single(results.Where(result => result.Status));
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM user_session;")));
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM external_identity;")));
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM contact_method WHERE verified_at IS NOT NULL;")));
        Assert.False((await federation.CompleteExternalAsync(new(attempt.Result.RelayState,
            Sign(key, attempt.Result.RequestId, database.Clock.UtcNow), application))).Status);
        Assert.False((await federation.RedeemAsync(redeem)).Status);
    }

    [MariaDbFact]
    public async Task DiscoveryOnlyProviderCannotTakeOverExistingAccountOrVerifyItsEmail()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var key = RSA.Create(2048);
        var application = Guid.NewGuid();
        await Register(database, application, key, false);
        using var scope = database.Scope(application);
        var identity = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var existing = await identity.EnsureAccountAsync(new("user@example.com", "Existing account"));
        Assert.True(existing.Status);
        await database.SqlAsync("UPDATE contact_method SET verified_at=UTC_TIMESTAMP(6) WHERE normalized=@email;", ("email", "user@example.com"));
        var federation = scope.ServiceProvider.GetRequiredService<IIdentityFederation>();
        Assert.Single((await federation.DiscoverAsync(new("user@example.com", application, "haley.identity"))).Result!);
        var attempt = await federation.BeginAsync(Start(application));
        var completed = await federation.CompleteExternalAsync(new(attempt.Result!.RelayState,
            Sign(key, attempt.Result.RequestId, database.Clock.UtcNow), application));
        Assert.True(completed.Status, completed.Message);
        var redeemed = await federation.RedeemAsync(new(application, completed.Result!.Code, Verifier));
        // An existing verified account cannot be linked through discovery-domain hints.
        Assert.False(redeemed.Status);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM external_identity;")));
    }

    [MariaDbFact]
    public async Task AttemptExpiryAndApplicationAllowlistAreEnforcedInPersistenceFlow()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var key = RSA.Create(2048);
        var application = Guid.NewGuid();
        await Register(database, application, key, true);
        using var scope = database.Scope(application);
        var federation = scope.ServiceProvider.GetRequiredService<IIdentityFederation>();
        using var other = database.Scope(Guid.NewGuid());
        Assert.False((await other.ServiceProvider.GetRequiredService<IIdentityFederation>().BeginAsync(Start(application))).Status);
        var attempt = await federation.BeginAsync(Start(application));
        Assert.True(attempt.Status);
        database.Clock.UtcNow = database.Clock.UtcNow.AddMinutes(20);
        Assert.False((await federation.CompleteExternalAsync(new(attempt.Result!.RelayState,
            Sign(key, attempt.Result.RequestId, database.Clock.UtcNow), application))).Status);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM federation_handoff;")));
    }

    private static BeginFederationRequest Start(Guid application) => new(application, "haley.identity", "corporate",
        ReturnUri, "browser-state-must-be-unpredictable", Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier))));

    private static async Task Register(IdentityDatabaseFixture database, Guid application, RSA key, bool authoritative)
    {
        database.Services.GetRequiredService<IOptions<IdentityServerOptions>>().Value.AllowedReturnUris[application.ToString("D")] = [ReturnUri];
        var result = await database.Services.GetRequiredService<IIdentityProviderAdministrationService>().UpsertProviderAsync(null,
            new("corporate", FederationProtocol.SignedCallback, "https://corporate.example", "Corporate", JsonSerializer.Serialize(new
            {
                authorizationUrl = "https://corporate.example/login", callbackUrl = "https://identity.example/identity/federation/external/callback",
                audience = "test-identity", keys = new[] { new { id = "current", pem = key.ExportSubjectPublicKeyInfoPem() } },
                allowedApplicationIds = new[] { application.ToString("D") }, defaultForApplicationIds = new[] { application.ToString("D") }, maximumAssertionSeconds = 120
            }), authoritative ? ["example.com"] : [], IdentityRecordStatus.Active, [], ["example.com"]));
        Assert.True(result.Status, result.Message);
    }

    private static string Sign(RSA key, Guid attempt, DateTimeOffset now)
    {
        var header = new JwtHeader(new SigningCredentials(new RsaSecurityKey(key) { KeyId = "current" }, SecurityAlgorithms.RsaSha256))
        { ["typ"] = "identity-bridge+jwt" };
        var payload = new JwtPayload("https://corporate.example", "test-identity", null, now.UtcDateTime, now.AddSeconds(90).UtcDateTime, now.UtcDateTime)
        {
            ["sub"] = "stable-corporate-subject", ["jti"] = Guid.NewGuid().ToString("N"), ["attempt"] = attempt.ToString("N"), ["contractVersion"] = 1,
            ["email"] = "user@example.com", ["email_verified"] = true, ["name"] = "Corporate User"
        };
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }
}
