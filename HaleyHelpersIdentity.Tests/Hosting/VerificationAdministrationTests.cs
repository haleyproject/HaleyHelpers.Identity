using Haley.Models;
using Haley.Security;
using Haley.Services;
using Haley.Utils;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class VerificationAdministrationTests
{
    [Theory]
    [InlineData(VerificationPurpose.EmailVerification, VerificationProofKind.NumericCode)]
    [InlineData(VerificationPurpose.EmailVerification, VerificationProofKind.OpaqueToken)]
    [InlineData(VerificationPurpose.PasswordReset, VerificationProofKind.NumericCode)]
    [InlineData(VerificationPurpose.PasswordReset, VerificationProofKind.OpaqueToken)]
    [InlineData(VerificationPurpose.PasswordlessLogin, VerificationProofKind.NumericCode)]
    [InlineData(VerificationPurpose.PasswordlessLogin, VerificationProofKind.OpaqueToken)]
    public async Task VerifiedAccountCanRepeatEmailVerificationAndUseRecoveryOrPasswordlessProofs(VerificationPurpose purpose, VerificationProofKind kind)
    {
        var store = VerifiedAccount();
        var service = CreateService(store, new TotpLoginAuthorization());
        var application = Guid.NewGuid();
        var started = await service.BeginForAdministrationAsync(application, "haley.identity",
            new(store.Subject.Email, purpose, kind, Context: "operator-simulation"));
        Assert.True(started.Status, started.Message);
        var delivery = Assert.IsType<IdentityVerificationDelivery>(started.Result.Delivery);
        var completion = new CompleteIdentityVerificationRequest(delivery.ChallengeId, purpose, delivery.Verifier, kind,
            "operator-simulation", purpose == VerificationPurpose.PasswordReset ? "Recovered#Password123" : null);
        var result = await service.CompleteForApplicationAsync(application, "haley.identity", completion);
        Assert.True(result.Status, result.Message); Assert.True(result.Result.EmailVerified);
        Assert.Equal(IdentityStatus.Active, result.Result.AccountStatus);
        Assert.Equal(purpose == VerificationPurpose.PasswordlessLogin, result.Result.Session is not null);
        Assert.False((await service.CompleteForApplicationAsync(application, "haley.identity", completion)).Status);
        if (purpose == VerificationPurpose.EmailVerification)
            Assert.NotNull((await service.BeginForAdministrationAsync(application, "haley.identity",
                new(store.Subject.Email, purpose, kind))).Result.Delivery);
    }

    [Theory]
    [InlineData(VerificationPurpose.PasswordlessLogin, IdentityStatus.Pending, true, true, false, true, "requires an Active account")]
    [InlineData(VerificationPurpose.PasswordlessLogin, IdentityStatus.Active, false, true, false, true, "Verify this email first")]
    [InlineData(VerificationPurpose.PasswordlessLogin, IdentityStatus.Active, true, false, false, true, "recovery is disabled")]
    [InlineData(VerificationPurpose.PasswordlessLogin, IdentityStatus.Active, true, true, true, true, "requires a password change")]
    [InlineData(VerificationPurpose.PasswordReset, IdentityStatus.Active, true, true, false, false, "no active password")]
    [InlineData(VerificationPurpose.Onboarding, IdentityStatus.Active, true, true, false, true, "choose Verify email")]
    public async Task OnlyOperatorIssuanceExplainsTheActualAccountRequirement(VerificationPurpose purpose, IdentityStatus status,
        bool verified, bool recovery, bool changeRequired, bool password, string expected)
    {
        var store = VerifiedAccount();
        store.Subject = store.Subject with { Identity = store.Subject.Identity with { Status = status, PasswordChangeRequired = changeRequired },
            VerifiedAt = verified ? store.Subject.VerifiedAt : null, RecoveryEnabled = recovery, CredentialId = password ? Guid.NewGuid() : null };
        var service = CreateService(store, new TotpLoginAuthorization());
        var application = Guid.NewGuid();
        var request = new BeginIdentityVerificationRequest(store.Subject.Email, purpose);
        var ordinary = await service.BeginForApplicationAsync(application, "haley.identity", request);
        Assert.True(ordinary.Status); Assert.Null(ordinary.Result.Delivery);
        var management = await service.BeginForAdministrationAsync(application, "haley.identity", request);
        Assert.False(management.Status); Assert.Equal(409, management.Code);
        Assert.Contains(expected, management.Message); Assert.Null(store.Challenge);
    }

    [Fact]
    public async Task AdministratorStillNeedsActiveApplicationAuthority()
    {
        var store = VerifiedAccount();
        var service = CreateService(store, new TotpLoginAuthorization { Permitted = false });
        var result = await service.BeginForAdministrationAsync(Guid.NewGuid(), "haley.identity",
            new(store.Subject.Email, VerificationPurpose.EmailVerification));
        Assert.False(result.Status); Assert.Equal(403, result.Code); Assert.Null(store.Challenge);
    }

    [Fact]
    public async Task StoreRejectionDoesNotLookLikeSuccessfulIssuanceForAnOperator()
    {
        var store = VerifiedAccount(); store.CanCreateChallenges = false;
        var service = CreateService(store, new TotpLoginAuthorization());
        var result = await service.BeginForAdministrationAsync(Guid.NewGuid(), "haley.identity",
            new(store.Subject.Email, VerificationPurpose.EmailVerification));
        Assert.False(result.Status); Assert.Equal(409, result.Code);
        Assert.Equal("verification_issuance_rejected", result.Key); Assert.Contains("cooldown", result.Message);
    }

    private static Haley.Tests.HostedVerificationStore VerifiedAccount()
    {
        var store = new Haley.Tests.HostedVerificationStore();
        store.Subject = store.Subject with { Identity = store.Subject.Identity with { Status = IdentityStatus.Active },
            VerifiedAt = new TestClock().UtcNow, RecoveryEnabled = true, CredentialId = Guid.NewGuid() };
        return store;
    }

    private static IdentityVerificationService CreateService(Haley.Tests.HostedVerificationStore store, TotpLoginAuthorization authorization)
    {
        var clock = new TestClock(); var options = Options.Create(new IdentityServerOptions { PasswordHashIterations = 100000 });
        var tokens = new SecretTokenGenerator(); var uuids = new Uuid7Generator(clock); var hasher = new Pbkdf2PasswordHasher(options);
        return new(store, new VerificationProofService(hasher, tokens, uuids, clock, options), new TestApplicationContext(),
            authorization, new Haley.Tests.HostedVerificationMfaPolicy(), hasher, tokens, uuids, clock, options);
    }
}
