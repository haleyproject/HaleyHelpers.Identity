using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Extensions;
using Haley.Constants;
using Haley.Hosting;
using Haley.Models;
using Haley.Security;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class MfaVerificationErrorTests
{
    [Fact]
    public async Task InvalidAndConsumedRecoveryCodesHaveUseful401FeedbackWhileServerFailuresRemain500()
    {
        var store = new TotpLoginStore(); var clock = new TestClock();
        var service = new MfaService(store, new AesGcmSecretProtector([new SecretProtectionKey("test", new byte[32], true)]),
            new SecretTokenGenerator(), new Uuid7Generator(clock), clock, Options.Create(new IdentityServerOptions()));
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
        await using var app = builder.Build(); IdentityHosting.ConfigureErrors(app);
        app.MapPost("/mfa/verification", async (VerifyMfaRequest request) => (await service.VerifyAsync(request)).ToMinimalApiResult());
        await app.StartAsync(); using var client = app.GetTestClient();
        const string recovery = "0123456789ABCDEF";
        var request = new VerifyMfaRequest(Guid.NewGuid(), null, MfaKind.RecoveryCode, recovery);
        using var invalid = await client.PostAsJsonAsync("/mfa/verification", request);
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        using var invalidJson = JsonDocument.Parse(await invalid.Content.ReadAsStringAsync());
        Assert.Equal("identity.mfa_invalid", invalidJson.RootElement.GetProperty("code").GetString());
        Assert.Contains("recovery code is invalid or has already been used", invalidJson.RootElement.GetProperty("detail").GetString());
        Assert.DoesNotContain(recovery, await invalid.Content.ReadAsStringAsync());
        store.AddRecovery(SHA256.HashData(Encoding.UTF8.GetBytes(recovery)));
        using var accepted = await client.PostAsJsonAsync("/mfa/verification", request); Assert.True(accepted.IsSuccessStatusCode);
        using var consumed = await client.PostAsJsonAsync("/mfa/verification", request); Assert.Equal(HttpStatusCode.Unauthorized, consumed.StatusCode);
        Assert.Contains("already been used", await consumed.Content.ReadAsStringAsync());
        store.RecoveryFailure = new IOException("Simulated storage failure.");
        using var unavailable = await client.PostAsJsonAsync("/mfa/verification", request);
        Assert.Equal(HttpStatusCode.InternalServerError, unavailable.StatusCode);
        using var serverJson = JsonDocument.Parse(await unavailable.Content.ReadAsStringAsync());
        Assert.Equal("identity_failure", serverJson.RootElement.GetProperty("code").GetString());
        Assert.DoesNotContain("recovery code is invalid", await unavailable.Content.ReadAsStringAsync());
        var methodId = Guid.NewGuid();
        store.Method = new(new(methodId, request.UserId, MfaKind.Totp, "Authenticator", IdentityRecordStatus.Active,
            clock.UtcNow, clock.UtcNow, null), null, null);
        using var unconfigured = await client.PostAsJsonAsync("/mfa/verification",
            new VerifyMfaRequest(request.UserId, methodId, MfaKind.Totp, "123456"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unconfigured.StatusCode);
        using var configurationJson = JsonDocument.Parse(await unconfigured.Content.ReadAsStringAsync());
        Assert.Equal("identity.secret_protection_unavailable", configurationJson.RootElement.GetProperty("code").GetString());
        Assert.Contains("SecretProtection", configurationJson.RootElement.GetProperty("detail").GetString());
    }

    [Theory]
    [InlineData("missing", IdentityErrorCodes.MfaEnrollmentInvalid)]
    [InlineData("expired", IdentityErrorCodes.MfaEnrollmentExpired)]
    [InlineData("consumed", IdentityErrorCodes.MfaEnrollmentConsumed)]
    [InlineData("locked", IdentityErrorCodes.MfaEnrollmentLocked)]
    [InlineData("locked-consumed", IdentityErrorCodes.MfaEnrollmentLocked)]
    [InlineData("attempt-consumed", IdentityErrorCodes.MfaEnrollmentLocked)]
    [InlineData("replaced-consumed", IdentityErrorCodes.MfaEnrollmentInvalid)]
    [InlineData("replaced", IdentityErrorCodes.MfaEnrollmentInvalid)]
    [InlineData("secret-missing", IdentityErrorCodes.SecretProtectionUnavailable)]
    public async Task EnrollmentInspectionAndConfirmationPreserveTheActualFailure(string state, string expected)
    {
        var (service, store, _) = EnrollmentFixture(state);
        var inspected = await service.InspectTotpEnrollmentAsync("private-ticket");
        var confirmed = await service.ConfirmTotpEnrollmentAsync(new("private-ticket", "123456"));

        Assert.False(inspected.Status);
        Assert.False(confirmed.Status);
        Assert.Equal(expected, inspected.Key);
        Assert.Equal(expected, confirmed.Key);
        Assert.Equal(expected == IdentityErrorCodes.SecretProtectionUnavailable ? 503 : 400, confirmed.Code);
        Assert.DoesNotContain("private-ticket", confirmed.Message);
        Assert.DoesNotContain("123456", confirmed.Message);
        Assert.Equal(0, store.EnrollmentFailures);
    }

    [Fact]
    public async Task RejectedCodeHasItsOwnReasonAndConsumesOnlyOneAttempt()
    {
        var (service, store, clock) = EnrollmentFixture("pending");
        var details = await service.InspectTotpEnrollmentAsync("private-ticket");
        Assert.True(details.Status);
        var secret = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(
            new Uri(details.Result.OtpauthUri).Query)["secret"].ToString();
        var expected = MfaPersistenceTests.Code(secret, clock.UtcNow);
        var wrong = expected == "000000" ? "000001" : "000000";
        var result = await service.ConfirmTotpEnrollmentAsync(new("private-ticket", wrong));

        Assert.False(result.Status);
        Assert.Equal(IdentityErrorCodes.MfaCodeInvalid, result.Key);
        Assert.Contains("did not match", result.Message);
        Assert.DoesNotContain(secret, result.Message);
        Assert.DoesNotContain(wrong, result.Message);
        Assert.Equal(1, store.EnrollmentFailures);
    }

    [Fact]
    public async Task UnreadableEnrollmentSecretDoesNotBecomeAnIncorrectCodeError()
    {
        var (service, store, _) = EnrollmentFixture("pending");
        store.Enrollment = store.Enrollment! with
        {
            Method = store.Enrollment.Method with { SecretEncrypted = [1, 2, 3] }
        };
        var inspected = await service.InspectTotpEnrollmentAsync("private-ticket");
        var confirmed = await service.ConfirmTotpEnrollmentAsync(new("private-ticket", "123456"));

        Assert.Equal(IdentityErrorCodes.SecretProtectionUnavailable, inspected.Key);
        Assert.Equal(IdentityErrorCodes.SecretProtectionUnavailable, confirmed.Key);
        Assert.Equal(0, store.EnrollmentFailures);
    }

    private static (MfaService Service, TotpLoginStore Store, TestClock Clock) EnrollmentFixture(string state)
    {
        var store = new TotpLoginStore();
        var clock = new TestClock();
        var protector = new AesGcmSecretProtector([new SecretProtectionKey("test", new byte[32], true)]);
        var options = new IdentityServerOptions();
        var methodId = Guid.NewGuid();
        var encrypted = protector.Protect(new byte[20], $"{options.MfaProtectionPurpose}:{methodId:N}");
        var method = new StoredMfaMethod(new(methodId, Guid.NewGuid(), MfaKind.Totp,
            "Private account", IdentityRecordStatus.Pending, clock.UtcNow, null, null), encrypted, null);
        var enrollment = new StoredMfaEnrollment(method, 0, 5, clock.UtcNow.AddMinutes(10), null, null, null);
        store.Enrollment = state switch
        {
            "missing" => null,
            "expired" => enrollment with { ExpiresAt = clock.UtcNow.AddSeconds(-1) },
            "consumed" => enrollment with { ConsumedAt = clock.UtcNow,
                Method = method with { Method = method.Method with { Status = IdentityRecordStatus.Active } } },
            "locked" => enrollment with { Attempts = 5 },
            "locked-consumed" => enrollment with { Attempts = 5, ConsumedAt = clock.UtcNow },
            "attempt-consumed" => enrollment with { Attempts = 4, ConsumedAt = clock.UtcNow },
            "replaced-consumed" => enrollment with { ConsumedAt = clock.UtcNow,
                Method = method with { Method = method.Method with { Status = IdentityRecordStatus.Retired } } },
            "replaced" => enrollment with { Method = method with { Method = method.Method with { Status = IdentityRecordStatus.Retired } } },
            "secret-missing" => enrollment with { Method = method with { SecretEncrypted = null } },
            _ => enrollment
        };
        return (new MfaService(store, protector, new SecretTokenGenerator(), new Uuid7Generator(clock),
            clock, Options.Create(options)), store, clock);
    }
}
