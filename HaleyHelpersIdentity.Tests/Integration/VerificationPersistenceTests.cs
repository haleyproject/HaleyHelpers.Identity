using Haley.Abstractions;
using Haley.Models;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class VerificationPersistenceTests
{
    [MariaDbFact]
    public async Task EmailVerificationKeepsAccountPendingAndOnboardingActivatesWithInitialPassword()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var scope = database.Scope(Guid.NewGuid()); var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("pending@example.test", InitialStatus: IdentityStatus.Pending));
        Assert.True(account.Status, account.Message); Assert.Equal(IdentityStatus.Pending, account.Result.Status);
        Assert.False((await client.GetEmailVerificationAsync("pending@example.test")).Result.IsVerified);
        Assert.False((await client.CreateApplicationSessionAsync(new("pending@example.test", false))).Status);
        await database.SqlAsync("UPDATE user_account SET flags=flags|4 WHERE normalized='pending@example.test'");
        var email = await Begin(client, VerificationPurpose.EmailVerification, "pending@example.test");
        var verified = await client.CompleteVerificationAsync(Complete(email));
        Assert.True(verified.Status, verified.Message); Assert.True(verified.Result.EmailVerified);
        Assert.Equal(IdentityStatus.Pending, verified.Result.AccountStatus); Assert.Null(verified.Result.Session);
        Assert.True((await client.GetEmailVerificationAsync("pending@example.test")).Result.RecoveryEnabled);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT flags&4 FROM user_account WHERE normalized='pending@example.test'")));
        var invitation = await Begin(client, VerificationPurpose.Onboarding, "pending@example.test", validity: 259200);
        Assert.Equal(database.Clock.UtcNow.AddDays(3), invitation.ExpiresAt);
        database.Clock.UtcNow = database.Clock.UtcNow.AddDays(2);
        var completed = await client.CompleteVerificationAsync(Complete(invitation) with { NewPassword = "Onboarding#Password1" });
        Assert.True(completed.Status, completed.Message); Assert.Equal(IdentityStatus.Active, completed.Result.AccountStatus);
        Assert.Null(completed.Result.Session); Assert.False((await client.CompleteVerificationAsync(Complete(invitation))).Status);
        Assert.True((await client.AuthenticatePasswordAsync(new("pending@example.test", "Onboarding#Password1"))).Status);
        var ensureAgain = await client.EnsureAccountAsync(new("pending@example.test", InitialStatus: IdentityStatus.Pending));
        Assert.Equal(IdentityStatus.Active, ensureAgain.Result.Status);
    }

    [MariaDbFact]
    public async Task ProofIsBoundToApplicationPurposeKindAndContextAndOnlyHashIsStored()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        Assert.True((await client.EnsureAccountAsync(new("bound@example.test"))).Status);
        var delivery = await Begin(client, VerificationPurpose.EmailVerification, "bound@example.test", context: "flow-123");
        var request = Complete(delivery) with { Context = "flow-123" };
        using var other = database.Scope(Guid.NewGuid());
        Assert.False((await other.ServiceProvider.GetRequiredService<IIdentity>().CompleteVerificationAsync(request)).Status);
        Assert.False((await client.CompleteVerificationAsync(request with { Purpose = VerificationPurpose.PasswordlessLogin })).Status);
        Assert.False((await client.CompleteVerificationAsync(request with { ProofKind = VerificationProofKind.NumericCode })).Status);
        Assert.False((await client.CompleteVerificationAsync(request with { Context = "another-flow" })).Status);
        Assert.False((await client.CompleteVerificationAsync(request with { NewPassword = "ShouldNotSet#123" })).Status);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT attempts FROM verification_challenge LIMIT 1")));
        Assert.Equal(32L, Convert.ToInt64(await database.SqlAsync("SELECT OCTET_LENGTH(link_hash) FROM challenge_data LIMIT 1")));
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM challenge_data WHERE link_hash=@hash",
            ("@hash", SHA256.HashData(Encoding.UTF8.GetBytes(delivery.Verifier))))));
        Assert.True((await client.CompleteVerificationAsync(request)).Status);
        Assert.False((await client.CompleteVerificationAsync(request)).Status);
    }

    [MariaDbFact]
    public async Task OtpLoginRequiresVerifiedContactAndProducesSingleApplicationBoundSession()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); var appId = Guid.NewGuid(); using var scope = database.Scope(appId);
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        Assert.True((await client.EnsureAccountAsync(new("otp@example.test"))).Status);
        var unavailable = await client.BeginVerificationAsync(new("otp@example.test", VerificationPurpose.PasswordlessLogin));
        Assert.True(unavailable.Status); Assert.Null(unavailable.Result.Delivery);
        await VerifyEmail(client, "otp@example.test");
        var delivery = await Begin(client, VerificationPurpose.PasswordlessLogin, "otp@example.test", VerificationProofKind.NumericCode);
        Assert.Matches("^[0-9]{6}$", delivery.Verifier);
        var result = await client.CompleteVerificationAsync(Complete(delivery));
        Assert.True(result.Status, result.Message); Assert.NotNull(result.Result.Session);
        Assert.True((await client.ValidateSessionAsync(result.Result.Session.Token)).Status);
        using var other = database.Scope(Guid.NewGuid());
        Assert.False((await other.ServiceProvider.GetRequiredService<IIdentity>().ValidateSessionAsync(result.Result.Session.Token)).Status);
        Assert.False((await client.CompleteVerificationAsync(Complete(delivery))).Status);
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM user_session_token")));
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM credential")));
    }

    [MariaDbFact]
    public async Task PasswordResetConsumesProofWithPasswordChangeAndRevokesExistingSessions()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("reset@example.test")); Assert.True(account.Status, account.Message);
        Assert.True((await client.SetPasswordAsync(account.Result.UserId, new("Original#Password1"))).Status);
        await VerifyEmail(client, "reset@example.test");
        var session = await client.AuthenticatePasswordAsync(new("reset@example.test", "Original#Password1")); Assert.True(session.Status);
        var proof = await Begin(client, VerificationPurpose.PasswordReset, "reset@example.test", VerificationProofKind.NumericCode);
        var completion = Complete(proof);
        Assert.False((await client.CompleteVerificationAsync(completion)).Status);
        Assert.False((await client.CompleteVerificationAsync(completion with { NewPassword = "Original#Password1" })).Status);
        var reset = await client.CompleteVerificationAsync(completion with { NewPassword = "Replacement#Password2" });
        Assert.True(reset.Status, reset.Message); Assert.Null(reset.Result.Session);
        Assert.False((await client.ValidateSessionAsync(session.Result.Token)).Status);
        Assert.False((await client.CompleteVerificationAsync(completion with { NewPassword = "Another#Password3" })).Status);
        Assert.True((await client.AuthenticatePasswordAsync(new("reset@example.test", "Replacement#Password2"))).Status);
        var stale = await Begin(client, VerificationPurpose.PasswordReset, "reset@example.test");
        Assert.True((await client.SetPasswordAsync(account.Result.UserId, new("Administrator#Password3"))).Status);
        Assert.False((await client.CompleteVerificationAsync(Complete(stale) with { NewPassword = "Stale#Password4" })).Status);
    }

    [MariaDbFact]
    public async Task ExpiredExhaustedAndSupersededVerifiersCannotBeUsed()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        Assert.True((await client.EnsureAccountAsync(new("expiry@example.test"))).Status);
        var expired = await Begin(client, VerificationPurpose.EmailVerification, "expiry@example.test", validity: 259200);
        database.Clock.UtcNow = database.Clock.UtcNow.AddDays(3);
        Assert.False((await client.CompleteVerificationAsync(Complete(expired))).Status);
        var first = await Begin(client, VerificationPurpose.EmailVerification, "expiry@example.test", VerificationProofKind.NumericCode);
        var throttled = await client.BeginVerificationAsync(new("expiry@example.test", VerificationPurpose.EmailVerification, VerificationProofKind.NumericCode));
        Assert.True(throttled.Status); Assert.Null(throttled.Result.Delivery);
        database.Clock.UtcNow = database.Clock.UtcNow.AddSeconds(301);
        var second = await Begin(client, VerificationPurpose.EmailVerification, "expiry@example.test", VerificationProofKind.NumericCode);
        Assert.False((await client.CompleteVerificationAsync(Complete(first))).Status);
        var wrong = second.Verifier == "000000" ? "111111" : "000000";
        for (var i = 0; i < 5; i++) Assert.False((await client.CompleteVerificationAsync(Complete(second) with { Verifier = wrong })).Status);
        Assert.False((await client.CompleteVerificationAsync(Complete(second))).Status);
        Assert.Null((await client.BeginVerificationAsync(new("expiry@example.test", VerificationPurpose.EmailVerification))).Result.Delivery);
    }

    [MariaDbFact]
    public async Task SessionFailureRollsBackProofConsumptionAndConcurrentCompletionsIssueOnlyOneSession()
    {
        await using (var database = await IdentityDatabaseFixture.CreateAsync(new RejectSessionExtension()))
        {
            using var scope = database.Scope(Guid.NewGuid()); var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
            Assert.True((await client.EnsureAccountAsync(new("rollback@example.test"))).Status); await VerifyEmail(client, "rollback@example.test");
            var proof = await Begin(client, VerificationPurpose.PasswordlessLogin, "rollback@example.test");
            await Assert.ThrowsAsync<InvalidOperationException>(() => client.CompleteVerificationAsync(Complete(proof)).AsTask());
            Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM user_session")));
            Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM verification_challenge WHERE status=1")));
        }
        await using (var database = await IdentityDatabaseFixture.CreateAsync())
        {
            var appId = Guid.NewGuid(); using var scope = database.Scope(appId); var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
            Assert.True((await client.EnsureAccountAsync(new("race-otp@example.test"))).Status); await VerifyEmail(client, "race-otp@example.test");
            var proof = await Begin(client, VerificationPurpose.PasswordlessLogin, "race-otp@example.test");
            var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
            {
                using var caller = database.Scope(appId);
                return await caller.ServiceProvider.GetRequiredService<IIdentity>().CompleteVerificationAsync(Complete(proof));
            }));
            Assert.Single(results, result => result.Status);
            Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM user_session_token")));
        }
    }

    [MariaDbFact]
    public async Task OnboardingCannotReactivateSuspendedAccountAndInvalidLifetimesAreRejected()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("state@example.test", InitialStatus: IdentityStatus.Pending)); Assert.True(account.Status);
        var proof = await Begin(client, VerificationPurpose.Onboarding, "state@example.test");
        Assert.True((await client.SetAccountStatusAsync(account.Result.UserId, new(IdentityStatus.Suspended, "test"))).Status);
        Assert.False((await client.CompleteVerificationAsync(Complete(proof))).Status);
        Assert.False((await client.BeginVerificationAsync(new("state@example.test", VerificationPurpose.EmailVerification, ValiditySeconds: 604801))).Status);
        Assert.False((await client.BeginVerificationAsync(new("state@example.test", VerificationPurpose.EmailVerification, VerificationProofKind.NumericCode, 259200))).Status);
        Assert.False((await client.EnsureAccountAsync(new("flags@example.test", InitialStatus: (IdentityStatus)3))).Status);
        var missing = await client.BeginVerificationAsync(new("missing@example.test", VerificationPurpose.Onboarding));
        Assert.True(missing.Status); Assert.Null(missing.Result.Delivery);
    }

    [MariaDbFact]
    public async Task EnrolledMfaRemainsRequiredAfterAValidEmailProof()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("otp-mfa@example.test")); Assert.True(account.Status);
        await VerifyEmail(client, "otp-mfa@example.test");
        var enrollment = await client.BeginTotpEnrollmentAsync(new(account.Result.UserId, "Test MFA")); Assert.True(enrollment.Status);
        var details = await client.InspectTotpEnrollmentAsync(enrollment.Result.Ticket); Assert.True(details.Status);
        var secret = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(details.Result.OtpauthUri).Query)["secret"].ToString();
        var confirmed = await client.ConfirmTotpEnrollmentAsync(new(enrollment.Result.Ticket, MfaPersistenceTests.Code(secret, database.Clock.UtcNow)));
        Assert.True(confirmed.Status, confirmed.Message);
        var recovery = await client.ReplaceRecoveryCodesAsync(new(account.Result.UserId, 5)); Assert.True(recovery.Status);
        var proof = await Begin(client, VerificationPurpose.PasswordlessLogin, "otp-mfa@example.test");
        var request = Complete(proof);
        var missing = await client.CompleteVerificationAsync(request); Assert.False(missing.Status); Assert.Equal("mfa_required", missing.Key);
        var rejected = await client.CompleteVerificationAsync(request with { MfaKind = MfaKind.RecoveryCode, MfaCode = "invalid" });
        Assert.False(rejected.Status); Assert.Equal("mfa_invalid", rejected.Key);
        var accepted = await client.CompleteVerificationAsync(request with { MfaKind = MfaKind.RecoveryCode, MfaCode = recovery.Result.Codes.First() });
        Assert.True(accepted.Status, accepted.Message); Assert.NotNull(accepted.Result.Session);
    }

    [MariaDbFact]
    public async Task EmailOnlyAccountsRecoverFromAutomaticLoginLockoutAfterExpiry()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("lock-otp@example.test", InitialStatus: IdentityStatus.Pending)); Assert.True(account.Status);
        var onboarding = await Begin(client, VerificationPurpose.Onboarding, "lock-otp@example.test");
        Assert.True((await client.CompleteVerificationAsync(Complete(onboarding))).Status);
        var proof = await Begin(client, VerificationPurpose.PasswordlessLogin, "lock-otp@example.test", VerificationProofKind.NumericCode);
        var wrong = proof.Verifier == "000000" ? "111111" : "000000";
        for (var i = 0; i < 5; i++) Assert.False((await client.CompleteVerificationAsync(Complete(proof) with { Verifier = wrong })).Status);
        Assert.Equal(IdentityStatus.Locked, (await client.GetAccountAsync(account.Result.UserId)).Result.Status);
        Assert.Null((await client.BeginVerificationAsync(new("lock-otp@example.test", VerificationPurpose.PasswordlessLogin))).Result.Delivery);
        database.Clock.UtcNow = database.Clock.UtcNow.AddMinutes(16);
        var afterLockout = await Begin(client, VerificationPurpose.PasswordlessLogin, "lock-otp@example.test");
        Assert.True((await client.CompleteVerificationAsync(Complete(afterLockout))).Status);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM credential")));
    }

    private static async Task VerifyEmail(IIdentity client, string email)
    {
        var proof = await Begin(client, VerificationPurpose.EmailVerification, email);
        var result = await client.CompleteVerificationAsync(Complete(proof)); Assert.True(result.Status, result.Message);
    }
    private static async Task<IdentityVerificationDelivery> Begin(IIdentity client, VerificationPurpose purpose, string email,
        VerificationProofKind kind = VerificationProofKind.OpaqueToken, int? validity = null, string? context = null)
    {
        var result = await client.BeginVerificationAsync(new(email, purpose, kind, validity, context));
        Assert.True(result.Status, result.Message); return Assert.IsType<IdentityVerificationDelivery>(result.Result.Delivery);
    }
    private static CompleteIdentityVerificationRequest Complete(IdentityVerificationDelivery proof) =>
        new(proof.ChallengeId, proof.Purpose, proof.Verifier, proof.ProofKind);
}
