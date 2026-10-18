using System.Security.Cryptography;
using System.Text;
using Haley.Abstractions;
using Haley.Constants;
using Haley.Models;
using Haley.Security;
using Haley.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class TotpAuthenticationTests
{
    private readonly Guid _application = Guid.NewGuid();
    private readonly TestClock _clock = new();
    private readonly TotpLoginStore _store = new();
    private readonly TotpLoginPolicy _policy = new();
    private readonly TotpLoginAuthorization _authorization = new();
    private readonly IdentityServerOptions _options = new() { TotpLogin = new() { Enabled = true } };
    private readonly TotpAuthenticationService _service;
    private readonly string _secret;
    private readonly MfaService _mfa;
    private readonly AesGcmSecretProtector _protector;
    private string Code => MfaPersistenceTests.Code(_secret, _clock.UtcNow);

    public TotpAuthenticationTests()
    {
        var id = Guid.NewGuid(); var method = Guid.NewGuid();
        _store.Subject = new(new(id, "Password-free account", IdentityStatus.Active, "person@example.test", _clock.UtcNow, null),
            Guid.NewGuid(), "person@example.test", _clock.UtcNow, true, null);
        var protector = _protector = new AesGcmSecretProtector([new SecretProtectionKey("test", RandomNumberGenerator.GetBytes(32), true)]);
        var seed = Encoding.ASCII.GetBytes("12345678901234567890");
        _secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        _store.Method = new(new(method, id, MfaKind.Totp, "Test authenticator", IdentityRecordStatus.Active, _clock.UtcNow,
            _clock.UtcNow, null), protector.Protect(seed, $"haley.identity.mfa.totp:{method:N}"), null);
        CryptographicOperations.ZeroMemory(seed);
        var mfa = _mfa = new MfaService(_store, protector, new SecretTokenGenerator(), new Uuid7Generator(_clock), _clock, Options.Create(_options));
        _service = new(_store, mfa, _authorization, _policy, _clock, Options.Create(_options));
    }

    [Fact]
    public async Task PasswordFreeAccountAuthenticatesAndCodeCannotBeReusedByAnotherApplication()
    {
        var result = await LoginAsync();
        Assert.True(result.Status, result.Message); Assert.Equal(_store.Subject!.Identity.UserId, result.Result.UserId);
        Assert.Null(_store.Subject.CredentialId);
        var replay = await _service.AuthenticateAsync(new("person@example.test", Code), Guid.NewGuid());
        Assert.False(replay.Status); Assert.Equal(IdentityErrorCodes.MfaCodeReused, replay.Key);
        _clock.UtcNow = _clock.UtcNow.AddSeconds(30);
        Assert.True((await LoginAsync()).Status);
    }

    [Fact]
    public async Task ConcurrentRequestsOnlyAcceptOneUseOfTheCode()
    {
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => LoginAsync())));
        Assert.Single(results.Where(result => result.Status));
    }

    [Theory]
    [InlineData(IdentityStatus.Pending)]
    [InlineData(IdentityStatus.Retired)]
    [InlineData(IdentityStatus.Locked)]
    public async Task InactiveAccountsCannotAuthenticate(IdentityStatus status)
    {
        _store.Subject = _store.Subject! with { Identity = _store.Subject.Identity with { Status = status } };
        Assert.Equal(status == IdentityStatus.Locked ? "identity.account_locked" : "invalid_credentials", (await LoginAsync()).Key);
        Assert.Null(_store.Method!.Method.LastUsedAt);
    }

    [Fact]
    public async Task UnverifiedEmailHasAnExplicitFailureWhileUnknownEmailAndWrongCodeRemainGeneric()
    {
        var unknown = await _service.AuthenticateAsync(new("unknown@example.test", Code), _application);
        _store.Subject = _store.Subject! with { VerifiedAt = null };
        var unverified = await LoginAsync();
        _store.Subject = _store.Subject with { VerifiedAt = _clock.UtcNow };
        var invalid = await _service.AuthenticateAsync(new("person@example.test", "123456" == Code ? "654321" : "123456"), _application);
        Assert.False(unverified.Status);
        Assert.Equal(IdentityErrorCodes.EmailUnverified, unverified.Key);
        Assert.Equal(403, unverified.Code);
        Assert.Contains("email address is not verified", unverified.Message); Assert.Equal(unknown.Key, invalid.Key);
         Assert.Equal(unknown.Message, invalid.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisabledOrUnlistedApplicationDoesNotConsumeTheAuthenticator(bool allowlist)
    {
        if (allowlist) _options.TotpLogin.ApplicationIds.Add(Guid.NewGuid());
        else _options.TotpLogin.Enabled = false;
        var result = await LoginAsync(); Assert.Equal("totp_login_disabled", result.Key); Assert.Equal(403, result.Code);
        Assert.Equal(0, _store.VerificationReads); Assert.Null(_store.Method!.Method.LastUsedAt);
    }

    [Fact]
    public async Task ResourceAuthorityAndExplicitMfaPolicyCannotBeBypassed()
    {
        _authorization.Permitted = false;
        Assert.Equal("invalid_client_resource", (await LoginAsync()).Key);
        _authorization.Permitted = true; _policy.RequireMfa = true;
        Assert.Equal("mfa_required", (await LoginAsync()).Key);
        Assert.Null(_store.Method!.Method.LastUsedAt);
    }

    [Fact]
    public async Task FailedGuessesLockTheAccountAndExpiredProtectionCanBeReleased()
    {
        var wrong = Code == "123456" ? "654321" : "123456";
        for (var index = 0; index < _options.MaximumFailedAttempts; index++)
        {
            var rejected = await _service.AuthenticateAsync(new("person@example.test", wrong), _application);
            Assert.False(rejected.Status);
            Assert.Equal(index == _options.MaximumFailedAttempts - 1 ? "identity.account_locked" : "invalid_credentials", rejected.Key);
        }
        Assert.Equal(_options.MaximumFailedAttempts, _store.MaximumAttempts);
        Assert.Equal(IdentityStatus.Locked, _store.Subject!.Identity.Status);
        Assert.False((await LoginAsync()).Status);
        _store.Attempts.Clear(); _store.UnlockExpired = true;
        Assert.True((await LoginAsync()).Status);
    }

    [Fact]
    public async Task RecoveryCodesAreOneUseAndCannotLogInWithoutAnActiveAuthenticator()
    {
        const string recovery = "TEST-RECOVERY-CODE";
        _store.AddRecovery(SHA256.HashData(Encoding.UTF8.GetBytes(recovery)));
        var request = new TotpAuthenticationRequest("person@example.test", recovery, Kind: MfaKind.RecoveryCode);
        Assert.True((await _service.AuthenticateAsync(request, _application)).Status);
        Assert.False((await _service.AuthenticateAsync(request, _application)).Status);
        _store.AddRecovery(SHA256.HashData(Encoding.UTF8.GetBytes(recovery)));
        _store.Method = _store.Method! with { Method = _store.Method.Method with { Status = IdentityRecordStatus.Retired } };
        Assert.False((await _service.AuthenticateAsync(request, _application)).Status);
    }

    [Fact]
    public async Task RetiringAccountDuringVerificationCannotIssueAnAuthenticatedSubject()
    {
        _store.OnConsumption = () => _store.Subject = _store.Subject! with { Identity = _store.Subject.Identity with { Status = IdentityStatus.Retired } };
        Assert.False((await LoginAsync()).Status);
    }

    [Fact]
    public async Task ForeignMethodAndPendingMethodCannotAuthenticate()
    {
        Assert.False((await _service.AuthenticateAsync(new("person@example.test", Code, Guid.NewGuid()), _application)).Status);
        _store.Method = _store.Method! with { Method = _store.Method.Method with { Status = IdentityRecordStatus.Pending } };
        Assert.False((await LoginAsync()).Status);
    }


    [Fact]
    public async Task AdminTestConsumesTheCodeAndPrimaryLoginAcceptsTheNextCode()
    {
        var test = await _mfa.VerifyAsync(new(_store.Subject!.Identity.UserId,
            _store.Method!.Method.MethodId, MfaKind.Totp, Code));
        Assert.True(test.Status);
        var login = await LoginAsync();
        Assert.False(login.Status);
        Assert.Equal(IdentityErrorCodes.MfaCodeReused, login.Key);
        Assert.Contains("Wait for the next code", login.Message);
        Assert.Equal("authenticator_code_reused", _store.Attempts.Last().ReasonCode);
        _clock.UtcNow = _clock.UtcNow.AddSeconds(30);
        Assert.True((await LoginAsync()).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnotherActiveAuthenticatorCanSucceedAfterAnUnreadableOlderSecret(bool explicitMethod)
    {
        var original = _store.Method!;
        var nextId = Guid.NewGuid();
        var valid = new StoredMfaMethod(original.Method with { MethodId = nextId },
            _protector.Protect(Encoding.ASCII.GetBytes("12345678901234567890"),
                $"haley.identity.mfa.totp:{nextId:N}"), null);
        _store.AdditionalMethods.Add(valid);
        _store.Method = original with { SecretEncrypted = [1, 2, 3] };

        var result = await _service.AuthenticateAsync(new("person@example.test", Code,
            explicitMethod ? nextId : null), _application);

        Assert.True(result.Status, result.Message);
        Assert.Null(_store.Method.Method.LastUsedAt);
        Assert.NotNull(_store.AdditionalMethods[0].Method.LastUsedAt);
    }

    [Fact]
    public async Task AnUnreadableSecretIsNotReportedAsAnIncorrectCodeOrCountedAsAGuess()
    {
        _store.Method = _store.Method! with { SecretEncrypted = [1, 2, 3] };
        var result = await LoginAsync();
        Assert.False(result.Status);
        Assert.Equal(IdentityErrorCodes.SecretProtectionUnavailable, result.Key);
        Assert.Equal(503, result.Code);
        Assert.Empty(_store.Attempts);
    }

    [Theory]
    [InlineData("unverified", "email_unverified")]
    [InlineData("password-change", "password_change_required")]
    [InlineData("inactive", "account_retired")]
    [InlineData("locked", "account_locked")]
    [InlineData("unknown", "account_not_found")]
    [InlineData("wrong-code", "authenticator_code_mismatch")]
    public async Task RealReasonsAreAuditedWithoutDisclosingAccountStateToAnonymousCallers(string state, string expected)
    {
        if (state == "unverified") _store.Subject = _store.Subject! with { VerifiedAt = null };
        if (state == "password-change")
            _store.Subject = _store.Subject! with { Identity = _store.Subject.Identity with { PasswordChangeRequired = true } };
        if (state == "inactive")
            _store.Subject = _store.Subject! with { Identity = _store.Subject.Identity with { Status = IdentityStatus.Retired } };
        if (state == "locked")
            _store.Subject = _store.Subject! with { Identity = _store.Subject.Identity with { Status = IdentityStatus.Locked } };
        var code = state == "wrong-code" ? Code == "000000" ? "000001" : "000000" : Code;
        var result = await _service.AuthenticateAsync(new(
            state == "unknown" ? "unknown@example.test" : "person@example.test", code), _application);

        Assert.False(result.Status);
        Assert.Equal(state switch
        {
            "locked" => IdentityErrorCodes.AccountLocked,
            "unverified" => IdentityErrorCodes.EmailUnverified,
            _ => "invalid_credentials"
        }, result.Key);
        Assert.Equal(expected, _store.Attempts.Last().ReasonCode);
        Assert.DoesNotContain(expected, result.Message);
        Assert.DoesNotContain(code, result.Message);
    }

    private Task<IFeedback<UserIdentity>> LoginAsync() => _service.AuthenticateAsync(new(" Person@Example.Test ", Code), _application).AsTask();
}
