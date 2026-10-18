using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;
using Xunit;
namespace Haley.Identity.Tests;

public sealed class IdentityPersistenceTests
{
    [MariaDbFact]
    public async Task AdministrativeVerificationRepairsRecoveryAndUnverificationInvalidatesOutstandingEmailProofs()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var identity = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var created = await identity.EnsureAccountAsync(new("operator@example.test")); Assert.True(created.Status, created.Message);
        var administration = scope.ServiceProvider.GetRequiredService<IdentityAdministrationService>();
        var store = scope.ServiceProvider.GetRequiredService<IdentityStore>();
        var contact = Assert.Single(await administration.EmailContactsAsync(created.Result.UserId, default));
        var contactUid = Convert.FromHexString(contact.ContactId.ToString("N"));
        // Reproduce a verified legacy/admin contact whose recovery flag was never set.
        await database.SqlAsync("UPDATE contact_method SET verified_at=@at,flags=flags&4294967293 WHERE uid=@uid",
            ("@at", database.Clock.UtcNow.UtcDateTime), ("@uid", contactUid));
        Assert.True(await store.OverrideEmailVerificationAsync(created.Result.UserId, contact.ContactId, "repair_recovery", database.Clock.UtcNow, default));
        contact = Assert.Single(await administration.EmailContactsAsync(created.Result.UserId, default));
        Assert.True(contact.IsVerified); Assert.True(contact.RecoveryEnabled);
        var issued = await identity.BeginVerificationAsync(new(contact.Email, VerificationPurpose.PasswordlessLogin)); Assert.True(issued.Status, issued.Message);
        var delivery = Assert.IsType<IdentityVerificationDelivery>(issued.Result.Delivery);
        var repeatedEmail = await identity.BeginVerificationAsync(new(contact.Email, VerificationPurpose.EmailVerification));
        var emailDelivery = Assert.IsType<IdentityVerificationDelivery>(repeatedEmail.Result.Delivery);
        await database.SqlAsync("""
            INSERT INTO verification_grant (uid,challenge_id,expires_at)
            SELECT @grant,id,@expires FROM verification_challenge WHERE uid=@challenge
            """, ("@grant", Convert.FromHexString(Guid.NewGuid().ToString("N"))),
            ("@expires", database.Clock.UtcNow.AddMinutes(5).UtcDateTime),
            ("@challenge", Convert.FromHexString(emailDelivery.ChallengeId.ToString("N"))));
        Assert.False((await administration.SetEmailVerificationAsync(Guid.NewGuid(), contact.ContactId,
            new(false, "wrong_account"), "test-operator", default)).Status);
        Assert.True((await administration.SetEmailVerificationAsync(created.Result.UserId, contact.ContactId,
            new(false, "operator_simulation"), "test-operator", default)).Status);
        contact = Assert.Single(await administration.EmailContactsAsync(created.Result.UserId, default));
        Assert.False(contact.IsVerified); Assert.False(contact.RecoveryEnabled);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM verification_grant WHERE expires_at>@at",
            ("@at", database.Clock.UtcNow.UtcDateTime))));
        Assert.Equal(IdentityStatus.Active, (await identity.GetAccountAsync(created.Result.UserId)).Result.Status);
        Assert.Null((await identity.BeginVerificationAsync(new(contact.Email, VerificationPurpose.PasswordlessLogin))).Result.Delivery);
        Assert.True((await administration.SetEmailVerificationAsync(created.Result.UserId, contact.ContactId,
            new(true, "operator_attestation"), "test-operator", default)).Status);
        Assert.False((await identity.CompleteVerificationAsync(new(delivery.ChallengeId, delivery.Purpose, delivery.Verifier))).Status);
        Assert.False((await identity.CompleteVerificationAsync(new(emailDelivery.ChallengeId, emailDelivery.Purpose, emailDelivery.Verifier))).Status);
        Assert.NotNull((await identity.BeginVerificationAsync(new(contact.Email, VerificationPurpose.PasswordlessLogin))).Result.Delivery);
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync(
            "SELECT COUNT(*) FROM outbox_data WHERE event_type LIKE '%.email.verification.withdrawn.v1'")));
    }

    [MariaDbFact]
    public async Task AdministrationResolvesRecordedMailboxesForAnAccountWithANonEmailUsername()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var scope = database.Scope(Guid.NewGuid());
        var identity = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var created = await identity.EnsureAccountAsync(new("mailbox@example.test")); Assert.True(created.Status, created.Message);
        var uid = Convert.FromHexString(created.Result.UserId.ToString("N"));
        await database.SqlAsync("UPDATE user_account SET normalized=@username WHERE uid=@uid", ("@username", "local-user"), ("@uid", uid));
        var administration = scope.ServiceProvider.GetRequiredService<IdentityAdministrationService>();
        var contacts = await administration.EmailContactsAsync(created.Result.UserId, default);
        var contact = Assert.Single(contacts);
        Assert.Equal("mailbox@example.test", contact.Email); Assert.NotEqual(Guid.Empty, contact.ContactId); Assert.False(contact.IsVerified);
        Assert.Empty(await administration.EmailContactsAsync(Guid.NewGuid(), default));
    }

    [MariaDbFact]
    public async Task MinimalAccountsAreSharedButOpaqueSessionsAreApplicationBoundAndFixedExpiry()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        var appA = Guid.NewGuid(); var appB = Guid.NewGuid();
        using var scopeA = database.Scope(appA); using var scopeB = database.Scope(appB);
        var a = scopeA.ServiceProvider.GetRequiredService<IIdentity>(); var b = scopeB.ServiceProvider.GetRequiredService<IIdentity>();
        var first = await a.EnsureAccountAsync(new("shared@example.test", SourceReference: "external-1"));
        Assert.True(first.Status, first.Message);
        var second = await b.EnsureAccountAsync(new("SHARED@example.test", SourceReference: "external-2"));
        Assert.True(second.Status, second.Message); Assert.Equal(first.Result.UserId, second.Result.UserId);
        var session = await a.CreateApplicationSessionAsync(new("shared@example.test", false));
        Assert.True(session.Status, session.Message); Assert.Equal(database.Clock.UtcNow.AddMinutes(30), session.Result.ExpiresAt);
        Assert.DoesNotContain(first.Result.UserId.ToString(), JsonSerializer.Serialize(session.Result));
        Assert.True((await a.ValidateSessionAsync(session.Result.Token)).Status);
        var resolved = await a.ResolveSessionAsync(session.Result.Token);
        Assert.True(resolved.Status, resolved.Message);
        Assert.Equal(first.Result.UserId, resolved.Result.UserId);
        Assert.Equal("shared@example.test", resolved.Result.Email);
        Assert.False(resolved.Result.EmailVerified);
        Assert.Equal(session.Result.SessionId, resolved.Result.SessionId);
        Assert.False((await b.ResolveSessionAsync(session.Result.Token)).Status);
        Assert.False((await b.ValidateSessionAsync(session.Result.Token)).Status);
        Assert.False((await b.RevokeSessionAsync(session.Result.Token)).Status);
        Assert.Equal(32L, Convert.ToInt64(await database.SqlAsync("SELECT OCTET_LENGTH(token_hash) FROM user_session_token LIMIT 1")));
        database.Clock.UtcNow = database.Clock.UtcNow.AddMinutes(31);
        Assert.False((await a.ValidateSessionAsync(session.Result.Token)).Status);
        Assert.False((await a.ResolveSessionAsync(session.Result.Token)).Status);
    }

    [MariaDbFact]
    public async Task PasswordLoginSupportsUsernamesAndCredentialReplacementInvalidatesPendingIssuance()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var scope = database.Scope(Guid.NewGuid()); var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var store = database.Services.GetRequiredService<IdentityStore>(); var hasher = database.Services.GetRequiredService<IPasswordHasher>();
        var hash = hasher.Hash("CorrectHorse123!"); var userId = Guid.NewGuid();
        Assert.True(await store.CreateLocalUserAsync(new(userId, Guid.NewGuid(), "local-user", "Local User", IdentityStatus.Active,
            hash.Value, hash.Algorithm, hash.ParametersPayload, false, database.Clock.UtcNow), default));
        var login = await client.AuthenticatePasswordAsync(new("local-user", "CorrectHorse123!"));
        Assert.True(login.Status, login.Message);
        var old = await store.FindLocalCredentialAsync("local-user", default);
        Assert.True((await client.SetPasswordAsync(userId, new("NewHorse456!"))).Status);
        Assert.False((await client.ValidateSessionAsync(login.Result.Token)).Status);
        var stale = await scope.ServiceProvider.GetRequiredService<IdentityService>().StartVerifiedSessionAsync(userId, old!.LocalCredentialId, ["pwd"]);
        Assert.False(stale.Status);
        Assert.False((await client.SetPasswordAsync(userId, new("CorrectHorse123!"))).Status);
    }

    [MariaDbFact]
    public async Task FailedPasswordsLockAccountAndReleaseCannotReactivateSuspendedAccount()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("lock@example.test")); Assert.True(account.Status, account.Message);
        Assert.True((await client.SetPasswordAsync(account.Result.UserId, new("CorrectHorse123!"))).Status);
        for (var i = 0; i < 5; i++) Assert.False((await client.AuthenticatePasswordAsync(new("lock@example.test", "bad"))).Status);
        Assert.Equal(IdentityStatus.Locked, (await client.GetAccountAsync(account.Result.UserId)).Result.Status);
        Assert.True((await client.ReleaseAccountLockAsync(account.Result.UserId)).Status);
        Assert.True((await client.SetAccountStatusAsync(account.Result.UserId, new(IdentityStatus.Suspended, "test"))).Status);
        Assert.False((await client.ReleaseAccountLockAsync(account.Result.UserId)).Status);
        Assert.False((await client.SetAccountStatusAsync(account.Result.UserId, new((IdentityStatus)3, "combined"))).Status);
    }

    [MariaDbFact]
    public async Task ConcurrentAccountCreationPreservesSingleSharedIdentity()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(async index =>
        {
            using var scope = database.Scope(Guid.NewGuid());
            return await scope.ServiceProvider.GetRequiredService<IIdentity>().EnsureAccountAsync(new("race@example.test", SourceReference: index.ToString()));
        }));
        Assert.All(results, result => Assert.True(result.Status, result.Message));
        Assert.Single(results.Select(result => result.Result.UserId).Distinct());
    }

    [MariaDbFact]
    public async Task PasswordRecoveryIsBoundToApplicationAndGrantIsSingleUse()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); var appId = Guid.NewGuid(); using var scope = database.Scope(appId);
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>(); var account = await client.EnsureAccountAsync(new("recover@example.test"));
        Assert.True(account.Status, account.Message); Assert.True((await client.SetPasswordAsync(account.Result.UserId, new("BeforeRecovery123!"))).Status);
        await database.SqlAsync("UPDATE contact_method SET flags=2,verified_at=@at WHERE normalized='recover@example.test'", ("@at", database.Clock.UtcNow.UtcDateTime));
        var reset = await client.BeginPasswordResetAsync(new(appId, "haley.identity", "email", "recover@example.test"));
        Assert.True(reset.Status, reset.Message); Assert.NotNull(reset.Result.Delivery);
        var delivery = reset.Result.Delivery!;
        using var other = database.Scope(Guid.NewGuid());
        var wrong = await other.ServiceProvider.GetRequiredService<IIdentity>().VerifyPasswordResetCodeAsync(new(delivery.ChallengeId, appId, "haley.identity", delivery.OneTimeCode));
        Assert.False(wrong.Status);
        var verified = await client.VerifyPasswordResetCodeAsync(new(delivery.ChallengeId, appId, "haley.identity", delivery.OneTimeCode));
        Assert.True(verified.Status, verified.Message);
        var request = new CompletePasswordResetRequest(verified.Result.GrantId, appId, "haley.identity", "AfterRecovery456!");
        Assert.True((await client.CompletePasswordResetAsync(request)).Status);
        Assert.False((await client.CompletePasswordResetAsync(request)).Status);
        Assert.True((await client.AuthenticatePasswordAsync(new("recover@example.test", "AfterRecovery456!"))).Status);
    }

    [MariaDbFact]
    public async Task RetiredEmailDoesNotLinkAnAccountOrLeaveAPartiallyCreatedAccount()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var original = await client.EnsureAccountAsync(new("retired@example.test")); Assert.True(original.Status, original.Message);
        await database.SqlAsync("UPDATE user_account SET normalized='current-user'; UPDATE contact_method SET retired_at=@at;", ("@at", database.Clock.UtcNow.UtcDateTime));
        Assert.False((await client.FindAccountAsync("retired@example.test")).Status);
        var attempted = await client.EnsureAccountAsync(new("retired@example.test"));
        Assert.False(attempted.Status); Assert.Equal("account_conflict", attempted.Key);
        Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM user_account")));
    }
}
