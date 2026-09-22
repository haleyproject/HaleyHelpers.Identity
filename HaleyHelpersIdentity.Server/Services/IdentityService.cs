using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class IdentityService(IdentityStore store, IMfaService mfa,
    IIdentityApplicationContext application, IPasswordHasher hasher,
    ISecretTokenGenerator tokens, IIdentityUuidGenerator uuids, IIdentityClock clock,
    IdentityCredentialVerifier credentials, IPasswordRecoveryService recovery, IOptions<IdentityServerOptions> options) : IIdentity
{
    public async ValueTask<IFeedback<UserIdentity>> GetAccountAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Found(await store.FindUserAsync(userId, cancellationToken).ConfigureAwait(false));

    public async ValueTask<IFeedback<UserIdentity>> FindAccountAsync(string email, CancellationToken cancellationToken = default) =>
        IdentityPolicy.TryNormalizeEmail(email, out var normalized)
            ? Found(await store.FindAccountByEmailAsync(normalized, cancellationToken).ConfigureAwait(false))
            : Fail<UserIdentity>("invalid_email", "A valid email address is required.");

    public async ValueTask<IFeedback<UserIdentity>> EnsureAccountAsync(EnsureAccountRequest request, CancellationToken cancellationToken = default)
    {
        var command = AccountCommand(request.Email, request.DisplayName, request.SourceReference);
        if (command is null) return Fail<UserIdentity>("invalid_account", "An application ID and valid account details are required.");
        var account = await store.EnsureAccountAsync(command, cancellationToken).ConfigureAwait(false);
        return account is null ? Fail<UserIdentity>("account_conflict", "The email or source identifier is associated with conflicting accounts.") : Ok(account);
    }

    public async ValueTask<IFeedback<UserIdentityPage>> ListAccountsAsync(UserPageRequest request, CancellationToken cancellationToken = default)
    {
        if (request.Page < 1 || request.PageSize is < 1 or > 100 || !Enum.IsDefined(request.Activity) || !Enum.IsDefined(request.Sort) ||
            (request.Status is not null && !Enum.IsDefined(request.Status.Value)))
            return Fail<UserIdentityPage>("invalid_query", "Account filters or pagination are invalid.");
        return Ok(await store.ListUserPageAsync(request, cancellationToken).ConfigureAwait(false));
    }

    public async ValueTask<IFeedback<UserProfile>> GetProfileAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Found(await store.FindUserProfileAsync(userId, cancellationToken).ConfigureAwait(false));

    public async ValueTask<IFeedback<UserProfile>> UpdateProfileAsync(Guid userId, UpdateUserProfileRequest request, CancellationToken cancellationToken = default)
    {
        try { IdentityPolicy.ValidateProfile(request); }
        catch (ArgumentException exception) { return Fail<UserProfile>("invalid_profile", exception.Message); }
        var changed = await store.UpdateUserProfileAsync(new(userId, IdentityPolicy.NormalizeDisplayName(request.DisplayName),
            IdentityPolicy.NormalizeOptionalName(request.GivenName), IdentityPolicy.NormalizeOptionalName(request.FamilyName),
            IdentityPolicy.NormalizeOptionalName(request.PreferredName), IdentityPolicy.NormalizeOptionalValue(request.Locale),
            IdentityPolicy.NormalizeOptionalValue(request.TimeZone), IdentityPolicy.NormalizeOptionalValue(request.AvatarUri), clock.UtcNow), cancellationToken).ConfigureAwait(false);
        return changed ? await GetProfileAsync(userId, cancellationToken).ConfigureAwait(false) : Fail<UserProfile>("account_not_found", "The account was not found or cannot be updated.");
    }

    public async ValueTask<IFeedback> SetAccountStatusAsync(Guid userId, AccountStatusRequest request, CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(request.Status) || string.IsNullOrWhiteSpace(request.Reason) || request.Reason.Length > 100)
            return Fail("invalid_status", "One valid status and a reason of at most 100 characters are required.");
        return await store.ChangeUserStatusAsync(userId, request.Status, request.Reason, clock.UtcNow, cancellationToken).ConfigureAwait(false)
            ? Ok() : Fail("account_state_conflict", "The account cannot transition to the requested state.");
    }

    public async ValueTask<IFeedback> SetPasswordAsync(Guid userId, SetPasswordRequest request, CancellationToken cancellationToken = default) =>
        await SetPasswordCoreAsync(userId, request.Password, request.RequirePasswordChange, null, cancellationToken).ConfigureAwait(false);

    public async ValueTask<IFeedback> ChangePasswordAsync(ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        var credential = await credentials.VerifyAsync(request.Username, request.CurrentPassword, cancellationToken).ConfigureAwait(false);
        if (credential is null) return Fail("invalid_credentials", "The supplied credentials were rejected.");
        return await SetPasswordCoreAsync(credential.UserId, request.NewPassword, false, credential.LocalCredentialId, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<IFeedback> SetPasswordCoreAsync(Guid userId, string password, bool requireChange, long? expectedCredentialId, CancellationToken cancellationToken)
    {
        try { IdentityPolicy.ValidateNewPassword(password); }
        catch (ArgumentException exception) { return Fail("invalid_password", exception.Message); }
        var hash = hasher.Hash(password);
        var changed = await store.SetCredentialAsync(new(userId, uuids.NewUuid7(), hash, requireChange, clock.UtcNow, expectedCredentialId),
            previous => hasher.Verify(password, previous.Value, previous.Algorithm, previous.ParametersPayload), cancellationToken).ConfigureAwait(false);
        return changed ? Ok() : Fail("password_change_rejected", "The account is unavailable, the credential changed concurrently, or the password was used recently.");
    }

    public async ValueTask<IFeedback<OpaqueSession>> AuthenticatePasswordAsync(PasswordAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        if (application.ApplicationId == Guid.Empty) return Fail<OpaqueSession>("application_required", "An application ID is required.");
        var credential = await credentials.VerifyAsync(request.Username, request.Password, cancellationToken).ConfigureAwait(false);
        var now = clock.UtcNow;
        if (credential is null)
        {
            var known = IdentityPolicy.TryNormalizeUsername(request.Username, out var normalized)
                ? await store.FindLocalCredentialAsync(normalized, cancellationToken).ConfigureAwait(false) : null;
            await store.RecordLoginAttemptAndApplyProtectionAsync(new(known?.UserId, Hash(request.Username ?? string.Empty), application.ApplicationId,
                "invalid_credential", "credential_rejected", null, null, now), options.Value.MaximumFailedAttempts, options.Value.LockoutSeconds, cancellationToken).ConfigureAwait(false);
            return Fail<OpaqueSession>("invalid_credentials", "The supplied credentials were rejected.");
        }
        if (credential.PasswordChangeRequired) return Fail<OpaqueSession>("password_change_required", "Change the initial password before starting a session.");
        var methods = await mfa.ListMethodsAsync(credential.UserId, cancellationToken).ConfigureAwait(false);
        var activeFactors = methods.Where(method => method.Status == IdentityRecordStatus.Active && method.Kind == MfaKind.Totp).ToArray();
        var authenticationMethods = new List<string> { "pwd" };
        if (activeFactors.Length > 0)
        {
            if (request.MfaKind is null || string.IsNullOrWhiteSpace(request.MfaCode))
                return Fail<OpaqueSession>("mfa_required", "This account requires its enrolled second factor.");
            var verified = await mfa.VerifyAsync(new(credential.UserId,
                request.MfaMethodId ?? (activeFactors.Length == 1 ? activeFactors[0].MethodId : null), request.MfaKind.Value, request.MfaCode), cancellationToken).ConfigureAwait(false);
            if (!verified.Status)
            {
                await store.RecordLoginAttemptAndApplyProtectionAsync(new(credential.UserId, Hash(request.Username), application.ApplicationId,
                    "invalid_credential", "mfa_invalid", null, null, now), options.Value.MaximumFailedAttempts, options.Value.LockoutSeconds, cancellationToken).ConfigureAwait(false);
                return Fail<OpaqueSession>("mfa_invalid", "The second factor was rejected.");
            }
            authenticationMethods.Add(request.MfaKind == MfaKind.Totp ? "totp" : "recovery");
        }
        await store.RecordLoginAttemptAndApplyProtectionAsync(new(credential.UserId, Hash(request.Username), application.ApplicationId,
            "success", null, null, null, now), options.Value.MaximumFailedAttempts, options.Value.LockoutSeconds, cancellationToken).ConfigureAwait(false);
        return await StartVerifiedSessionAsync(credential.UserId, credential.LocalCredentialId, authenticationMethods, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Server-only issuance after the owning host has verified the subject and applied its policies.</summary>
    public async ValueTask<IFeedback<OpaqueSession>> StartVerifiedSessionAsync(Guid userId, long? credentialId,
        IReadOnlyCollection<string> authenticationMethods, CancellationToken cancellationToken = default)
    {
        if (application.ApplicationId == Guid.Empty || userId == Guid.Empty)
            return Fail<OpaqueSession>("invalid_account", "An application and verified account are required.");
        var now = clock.UtcNow;
        var account = new EnsureAccountCommand(userId, Guid.Empty, application.ApplicationId, string.Empty, string.Empty, null, now);
        var sessionId = uuids.NewUuid7();
        var token = tokens.Generate();
        var expiresAt = now.AddSeconds(options.Value.SessionSeconds);
        return await store.StartOpaqueSessionAsync(new(account, false, sessionId, token.Hash, expiresAt,
            authenticationMethods, credentialId, userId, application.OwnerContext), cancellationToken).ConfigureAwait(false)
            ? Ok(new OpaqueSession(sessionId, token.Value, expiresAt))
            : Fail<OpaqueSession>("session_rejected", "The account or verified credential changed before the session could start.");
    }

    public ValueTask<IFeedback<OpaqueSession>> CreateApplicationSessionAsync(ApplicationSessionRequest request, CancellationToken cancellationToken = default) =>
        StartSessionAsync(request, ["application_asserted"], cancellationToken);

    private async ValueTask<IFeedback<OpaqueSession>> StartSessionAsync(ApplicationSessionRequest request,
        IReadOnlyCollection<string> authenticationMethods, CancellationToken cancellationToken)
    {
        var account = AccountCommand(request.Email, request.DisplayName, request.SourceReference);
        if (account is null) return Fail<OpaqueSession>("invalid_account", "An application ID and valid email address are required.");
        var sessionId = uuids.NewUuid7();
        var token = tokens.Generate();
        var expiresAt = clock.UtcNow.AddSeconds(options.Value.SessionSeconds);
        return await store.StartOpaqueSessionAsync(new(account, request.CreateIfMissing, sessionId, token.Hash, expiresAt, authenticationMethods, OwnerContext: application.OwnerContext), cancellationToken).ConfigureAwait(false)
            ? Ok(new OpaqueSession(sessionId, token.Value, expiresAt))
            : Fail<OpaqueSession>("session_rejected", "The account was not found, is unavailable, or has conflicting identity associations.");
    }

    public async ValueTask<IFeedback<SessionValidation>> ValidateSessionAsync(string token, CancellationToken cancellationToken = default)
    {
        if (!ValidToken(token)) return Fail<SessionValidation>("invalid_session", "The session token or application context is invalid.");
        var session = await store.ValidateOpaqueSessionAsync(application.ApplicationId, tokens.Hash(token), clock.UtcNow, cancellationToken, application.OwnerContext).ConfigureAwait(false);
        return session is null ? Fail<SessionValidation>("invalid_session", "The session is unavailable, expired, revoked, or belongs to another application.") : Ok(session);
    }

    public async ValueTask<IFeedback> RevokeSessionAsync(string token, CancellationToken cancellationToken = default)
    {
        if (!ValidToken(token)) return Fail("invalid_session", "The session token or application context is invalid.");
        var validation = await ValidateSessionAsync(token, cancellationToken).ConfigureAwait(false);
        if (!validation.Status) return Fail("invalid_session", validation.Message ?? "The session is unavailable.");
        return await store.RevokeOpaqueSessionAsync(application.ApplicationId, tokens.Hash(token), clock.UtcNow, cancellationToken).ConfigureAwait(false)
            ? Ok() : Fail("invalid_session", "The session was not found for this application.");
    }

    public async ValueTask<IFeedback<UserLoginAttemptPage>> ListLoginAttemptsAsync(UserLoginAttemptSearchRequest request, CancellationToken cancellationToken = default) =>
        Ok(await store.ListUserLoginAttemptsAsync(request, cancellationToken).ConfigureAwait(false));

    public async ValueTask<IFeedback> ReleaseAccountLockAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await store.ChangeUserStatusAsync(userId, IdentityStatus.Active, "application_lock_release", clock.UtcNow, cancellationToken, IdentityStatus.Locked).ConfigureAwait(false)
            ? Ok() : Fail("account_state_conflict", "The account lock cannot be released.");

    public async ValueTask<IFeedback<IReadOnlyCollection<MfaMethodInfo>>> ListMfaMethodsAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Ok(await mfa.ListMethodsAsync(userId, cancellationToken).ConfigureAwait(false));
    public ValueTask<IFeedback<TotpEnrollmentReceipt>> BeginTotpEnrollmentAsync(BeginTotpEnrollmentRequest request, CancellationToken cancellationToken = default) =>
        mfa.BeginTotpEnrollmentAsync(request with { ApplicationId = application.ApplicationId }, cancellationToken);
    public ValueTask<IFeedback<TotpEnrollmentDetails>> InspectTotpEnrollmentAsync(string ticket, CancellationToken cancellationToken = default) => mfa.InspectTotpEnrollmentAsync(ticket, cancellationToken);
    public ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpEnrollmentAsync(ConfirmTotpTicketRequest request, CancellationToken cancellationToken = default) => mfa.ConfirmTotpEnrollmentAsync(request, cancellationToken);
    public ValueTask<IFeedback> RetireMfaMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default) => mfa.RetireMethodAsync(userId, methodId, cancellationToken);
    public ValueTask<IFeedback<RecoveryCodesReceipt>> ReplaceRecoveryCodesAsync(ReplaceRecoveryCodesRequest request, CancellationToken cancellationToken = default) => mfa.ReplaceRecoveryCodesAsync(request, cancellationToken);
    public ValueTask<IFeedback> VerifyMfaAsync(VerifyMfaRequest request, CancellationToken cancellationToken = default) => mfa.VerifyAsync(request, cancellationToken);

    public ValueTask<IFeedback<PasswordResetInitiationResult>> BeginPasswordResetAsync(BeginPasswordResetRequest request, CancellationToken cancellationToken = default) =>
        recovery.BeginResetAsync(request with { ApplicationId = application.ApplicationId, Context = application.OwnerContext ?? "haley.identity" }, cancellationToken);

    public ValueTask<IFeedback<PasswordResetGrantReceipt>> VerifyPasswordResetCodeAsync(VerifyPasswordResetCodeRequest request, CancellationToken cancellationToken = default) =>
        recovery.VerifyResetCodeAsync(request with { ApplicationId = application.ApplicationId, Context = application.OwnerContext ?? "haley.identity" }, cancellationToken);

    public ValueTask<IFeedback<PasswordResetCompletionReceipt>> CompletePasswordResetAsync(CompletePasswordResetRequest request, CancellationToken cancellationToken = default) =>
        recovery.CompleteResetAsync(request with { ApplicationId = application.ApplicationId, Context = application.OwnerContext ?? "haley.identity" }, cancellationToken);

    private EnsureAccountCommand? AccountCommand(string email, string? displayName, string? source)
    {
        if (application.ApplicationId == Guid.Empty || !IdentityPolicy.TryNormalizeEmail(email, out var normalized) || source?.Length > 1000) return null;
        try { return new(uuids.NewUuid7(), uuids.NewUuid7(), application.ApplicationId, normalized,
            IdentityPolicy.NormalizeDisplayName(displayName ?? normalized), string.IsNullOrWhiteSpace(source) ? null : Hash(source), clock.UtcNow); }
        catch (ArgumentException) { return null; }
    }
    private bool ValidToken(string? token) => application.ApplicationId != Guid.Empty && !string.IsNullOrWhiteSpace(token) && token.Length <= 512;
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static IFeedback<T> Found<T>(T? value) where T : class => value is null ? Fail<T>("account_not_found", "The account was not found.") : Ok(value);
    private static IFeedback Ok() => new Feedback(true, "Identity operation completed.") { Source = "Haley.Identity" };
    private static IFeedback<T> Ok<T>(T value) => new Feedback<T>(true, "Identity operation completed.", value) { Source = "Haley.Identity" };
    private static int ErrorStatus(string key) => key == "account_not_found" ? 404 :
        key is "invalid_credentials" or "invalid_session" or "mfa_invalid" ? 401 :
        key.EndsWith("conflict", StringComparison.Ordinal) || key == "session_rejected" ? 409 : 400;
    private static IFeedback Fail(string key, string message) => new Feedback(false, message) { Code = ErrorStatus(key), Key = key, Source = "Haley.Identity" };
    private static IFeedback<T> Fail<T>(string key, string message) => new Feedback<T>(false, message) { Code = ErrorStatus(key), Key = key, Source = "Haley.Identity" };
}
