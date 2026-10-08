using Microsoft.Extensions.Options;

namespace Haley.Services;

/// <summary>Shared primary authenticator proof, policy, account state and login protection.</summary>
public sealed class TotpAuthenticationService(IIdentityVerificationStore store, IMfaService mfa,
    IIdentityRecoveryAuthorization authorization, ITotpAuthenticationPolicy policy,
    IIdentityClock clock, IOptions<IdentityServerOptions> options)
{
    public async ValueTask<IFeedback<UserIdentity>> AuthenticateAsync(TotpAuthenticationRequest request,
        Guid applicationId, string? ownerContext = null, CancellationToken cancellationToken = default)
    {
        if (applicationId == Guid.Empty || !IdentityPolicy.TryNormalizeEmail(request.Email, out var email) ||
            request.MethodId == Guid.Empty || request.Kind is not (MfaKind.Totp or MfaKind.RecoveryCode) ||
            string.IsNullOrWhiteSpace(request.Code) || request.Code.Length > 128 ||
            request.Kind == MfaKind.Totp && (request.Code.Trim().Length != 6 || !request.Code.Trim().All(char.IsAsciiDigit)))
            return Fail("invalid_request", "A valid email and authenticator or recovery code are required.", 400);
        if (!authorization.TryNormalizeContext(ownerContext ?? "haley.identity", out var context) ||
            !await authorization.HasActiveResourceAuthorityAsync(applicationId, context, cancellationToken).ConfigureAwait(false))
            return Fail("invalid_client_resource", "The application is not authorized for this identity context.", 403);
        var settings = options.Value;
        if (!settings.TotpLogin.Enabled || settings.TotpLogin.ApplicationIds.Count > 0 &&
            !settings.TotpLogin.ApplicationIds.Contains(applicationId))
            return Fail("totp_login_disabled", "Primary authenticator login is disabled for this application.", 403);

        var subject = await store.FindVerificationSubjectAsync(email, cancellationToken).ConfigureAwait(false);
        if (subject?.Identity.Status == IdentityStatus.Locked &&
            await store.ReleaseExpiredLoginProtectionAsync(subject.Identity.UserId, clock.UtcNow, cancellationToken).ConfigureAwait(false))
            subject = await store.FindVerificationSubjectAsync(email, cancellationToken).ConfigureAwait(false);
        if (!CanAuthenticate(subject)) return await RejectAsync(subject, email, applicationId, cancellationToken).ConfigureAwait(false);
        var permitted = await policy.AuthorizeAsync(applicationId, context, subject!, cancellationToken).ConfigureAwait(false);
        if (!permitted.Status)
            return Fail(permitted.Key ?? "authentication_rejected", permitted.Message ?? "Primary authenticator login was rejected.",
                permitted.Code is >= 400 and <= 599 ? permitted.Code : 403);

        var methods = (await mfa.ListMethodsAsync(subject!.Identity.UserId, cancellationToken).ConfigureAwait(false))
            .Where(method => method.UserId == subject.Identity.UserId && method.Status == IdentityRecordStatus.Active && method.Kind == MfaKind.Totp)
            .ToArray();
        var verified = false;
        if (methods.Length > 0)
        {
            var candidates = request.Kind == MfaKind.RecoveryCode ? new Guid?[] { null } :
                methods.Where(method => request.MethodId is null || method.MethodId == request.MethodId)
                    .Select(method => (Guid?)method.MethodId).ToArray();
            foreach (var methodId in candidates)
            {
                var proof = await mfa.VerifyAsync(new(subject.Identity.UserId, methodId, request.Kind, request.Code.Trim()), cancellationToken).ConfigureAwait(false);
                if (!proof.Status)
                {
                    if (proof.Key == IdentityErrorCodes.SecretProtectionUnavailable)
                        return Fail(proof.Key, "Secret protection is unavailable for authenticator verification.", 503);
                    continue;
                }
                verified = true;
                break;
            }
        }
        if (!verified) return await RejectAsync(subject, email, applicationId, cancellationToken).ConfigureAwait(false);

        // Recheck identity after consuming the proof so retirement, lockout or contact changes cannot issue a session.
        var current = await store.FindVerificationSubjectAsync(email, cancellationToken).ConfigureAwait(false);
        if (!CanAuthenticate(current) || current!.Identity.UserId != subject.Identity.UserId || current.ContactId != subject.ContactId)
            return Fail("invalid_credentials", "The supplied credentials were rejected.", 401);
        await store.RecordLoginAttemptAndApplyProtectionAsync(new(current.Identity.UserId, VerificationProofService.Hash(email),
            applicationId, "success", null, null, null, clock.UtcNow), settings.MaximumFailedAttempts,
            settings.LockoutSeconds, cancellationToken).ConfigureAwait(false);
        return new Feedback<UserIdentity>(true, "Authenticator login verified.", current.Identity) { Source = "Haley.Identity" };
    }

    private static bool CanAuthenticate(StoredVerificationSubject? subject) =>
        subject is not null && subject.Identity.Status == IdentityStatus.Active && subject.VerifiedAt is not null &&
        !subject.Identity.PasswordChangeRequired;

    private async ValueTask<IFeedback<UserIdentity>> RejectAsync(StoredVerificationSubject? subject, string email,
        Guid applicationId, CancellationToken cancellationToken)
    {
        await store.RecordLoginAttemptAndApplyProtectionAsync(new(subject?.Identity.UserId, VerificationProofService.Hash(email),
            applicationId, "invalid_credential", "authenticator_rejected", null, null, clock.UtcNow),
            options.Value.MaximumFailedAttempts, options.Value.LockoutSeconds, cancellationToken).ConfigureAwait(false);
        return Fail("invalid_credentials", "The supplied credentials were rejected.", 401);
    }

    private static IFeedback<UserIdentity> Fail(string key, string message, int code) =>
        new Feedback<UserIdentity>(false, message) { Key = key, Code = code, Source = "Haley.Identity" };
}
