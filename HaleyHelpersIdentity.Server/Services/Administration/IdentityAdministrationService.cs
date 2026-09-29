namespace Haley.Services;

/// <summary>Account administration used behind a host's management authorization boundary.</summary>
public sealed class IdentityAdministrationService(IdentityStore store, IdentityService identity, IMfaService mfa,
    IPasswordHasher hasher, IIdentityUuidGenerator uuids, IIdentityClock clock)
{
    public ValueTask<IFeedback<UserIdentity>> CreateAsync(CreateLocalUserRequest request, CancellationToken ct) =>
        LocalAccountRegistration.CreateAsync(request, hasher, uuids, clock, store.CreateLocalUserAsync, ct);

    public async ValueTask<IFeedback<UserProfile>> UpdateDisplayNameAsync(Guid userId, string name, CancellationToken ct)
    {
        var found = await identity.GetProfileAsync(userId, ct).ConfigureAwait(false);
        if (!found.Status || found.Result is null) return found;
        var p = found.Result;
        return await identity.UpdateProfileAsync(userId, new(name, p.GivenName, p.FamilyName, p.PreferredName, p.Locale, p.TimeZone, p.AvatarUri), ct).ConfigureAwait(false);
    }

    public async ValueTask<IFeedback> RestoreAsync(Guid userId, AdminLifecycleAction request, CancellationToken ct) =>
        ValidReason(request.ReasonCode) && await store.RestoreUserAsync(userId, request.ReasonCode, clock.UtcNow, ct).ConfigureAwait(false) ? Ok() : Fail("account_state_conflict");

    public async ValueTask<IFeedback> DeleteAsync(Guid userId, AdminPermanentDelete request, CancellationToken ct) =>
        ValidReason(request.ReasonCode) && request.Confirmation == userId.ToString("D") &&
        await store.PermanentlyDeleteUserAsync(userId, request.ReasonCode, clock.UtcNow, ct).ConfigureAwait(false) ? Ok() : Fail("account_state_conflict");

    public ValueTask<AccountSessionPage> SessionsAsync(Guid userId, bool activeOnly, int page, CancellationToken ct) =>
        store.ListAccountSessionsAsync(userId, activeOnly, page, clock.UtcNow, ct);
    public async ValueTask<IFeedback> RevokeSessionAsync(Guid sessionId, CancellationToken ct) =>
        await store.RevokeAccountSessionAsync(sessionId, clock.UtcNow, ct).ConfigureAwait(false) ? Ok() : Fail("session_unavailable");

    public async ValueTask<IFeedback<BulkPasswordResetResponse>> ResetPasswordsAsync(BulkPasswordResetRequest request, CancellationToken ct)
    {
        try { IdentityPolicy.ValidateNewPassword(request.NewPassword); }
        catch (ArgumentException) { return new Feedback<BulkPasswordResetResponse>(false, "The password does not satisfy the password policy.") { Code = 400, Key = "invalid_password" }; }
        if (request.UserIds is null || request.UserIds.Count is < 1 or > 500 || !ValidReason(request.ReasonCode))
            return new Feedback<BulkPasswordResetResponse>(false, "Select between one and 500 accounts and supply a reason.") { Code = 400, Key = "invalid_request" };
        var rows = new List<BulkPasswordResetRowResult>();
        foreach (var userId in request.UserIds.Distinct())
        {
            var result = await identity.SetPasswordAsync(userId, new(request.NewPassword, request.RequirePasswordChange), ct).ConfigureAwait(false);
            rows.Add(new(userId, result.Status, result.Status ? null : result.Key));
        }
        return new Feedback<BulkPasswordResetResponse>(true, "Password reset batch completed.",
            new(rows.Count, rows.Count(row => row.Succeeded), rows.Count(row => !row.Succeeded), rows));
    }

    public async ValueTask<IFeedback<AdminTotpEnrollment>> BeginTotpAsync(Guid userId, AdminBeginTotpEnrollment request, CancellationToken ct)
    {
        var started = await mfa.BeginTotpEnrollmentAsync(new(userId, request.AccountLabel, ReplaceMethodId: request.ReplaceMethodId), ct).ConfigureAwait(false);
        if (!started.Status || started.Result is null) return new Feedback<AdminTotpEnrollment>(false, started.Message) { Key = started.Key, Code = started.Code };
        try
        {
            var details = await mfa.InspectTotpEnrollmentAsync(started.Result.Ticket, ct).ConfigureAwait(false);
            if (!details.Status || details.Result is null)
            {
                await mfa.RetireMethodAsync(userId, started.Result.MethodId, CancellationToken.None).ConfigureAwait(false);
                return new Feedback<AdminTotpEnrollment>(false, details.Message) { Key = details.Key, Code = details.Code };
            }
            return new Feedback<AdminTotpEnrollment>(true, "Authenticator enrollment prepared.", new(started.Result.MethodId,
                started.Result.Ticket, QrCodeBuilder.CreateSvg(details.Result.OtpauthUri), started.Result.ExpiresAt,
                details.Result.AttemptsRemaining, request.ReplaceMethodId.HasValue));
        }
        catch
        {
            await mfa.RetireMethodAsync(userId, started.Result.MethodId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpAsync(Guid userId, AdminConfirmTotpEnrollment request, CancellationToken ct)
    {
        var details = await mfa.InspectTotpEnrollmentAsync(request.Ticket, ct).ConfigureAwait(false);
        if (!details.Status || details.Result?.UserId != userId) return new Feedback<TotpEnrollmentCompletion>(false, "The enrollment does not belong to this account.") { Key = "mfa_invalid", Code = 400 };
        return await mfa.ConfirmTotpEnrollmentAsync(new(request.Ticket, request.Code), ct).ConfigureAwait(false);
    }
    private static bool ValidReason(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100;
    private static IFeedback Ok() => new Feedback(true, "Account administration completed.");
    private static IFeedback Fail(string key) => new Feedback(false, "The account operation was rejected.") { Key = key, Code = 409 };
}
