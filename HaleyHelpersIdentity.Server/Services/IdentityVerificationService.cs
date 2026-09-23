using System.Text.Json;
using Microsoft.Extensions.Options;
using static Haley.Services.IdentityVerificationPolicy;

namespace Haley.Services;

/// <summary>Purpose-bound email verification and login, with delivery delegated to the calling application.</summary>
public sealed class IdentityVerificationService(IIdentityVerificationStore store, VerificationProofService proofs,
    IIdentityApplicationContext application, IIdentityRecoveryAuthorization authorization, IIdentityVerificationMfaPolicy mfa,
    IPasswordHasher hasher, ISecretTokenGenerator tokens, IIdentityUuidGenerator uuids, IIdentityClock clock,
    IOptions<IdentityServerOptions> options)
{
    public async ValueTask<IFeedback<EmailVerificationInfo>> GetEmailVerificationAsync(string email, CancellationToken cancellationToken = default)
    {
        if (!IdentityPolicy.TryNormalizeEmail(email, out var normalized)) return Fail<EmailVerificationInfo>("invalid_email", "A valid email address is required.");
        if (await AuthorizedContextAsync(cancellationToken).ConfigureAwait(false) is null) return Denied<EmailVerificationInfo>();
        var subject = await store.FindVerificationSubjectAsync(normalized, cancellationToken).ConfigureAwait(false);
        return subject is null ? Fail<EmailVerificationInfo>("account_not_found", "The email contact was not found.", 404) :
            Ok(new EmailVerificationInfo(subject.Identity.UserId, subject.Email, subject.VerifiedAt, subject.RecoveryEnabled));
    }

    public async ValueTask<IFeedback<IdentityVerificationInitiation>> BeginAsync(BeginIdentityVerificationRequest request, CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(request.Purpose) || !Enum.IsDefined(request.ProofKind) || request.Context?.Length > 1000 ||
            !IdentityPolicy.TryNormalizeEmail(request.Email, out var email))
            return Fail<IdentityVerificationInitiation>("invalid_request", "A valid email, single purpose and proof kind are required.");
        var settings = options.Value.Verification;
        var validity = request.ValiditySeconds ?? (request.ProofKind == VerificationProofKind.NumericCode ? settings.CodeValiditySeconds :
            request.Purpose == VerificationPurpose.PasswordlessLogin ? settings.LinkProofSeconds :
            request.Purpose == VerificationPurpose.PasswordReset ? settings.PasswordResetSeconds : settings.ActivationLinkSeconds);
        var maximum = request.ProofKind == VerificationProofKind.NumericCode ? settings.MaximumCodeValiditySeconds : settings.MaximumTokenValiditySeconds;
        if (validity < 60 || validity > maximum)
            return Fail<IdentityVerificationInitiation>("invalid_expiry", $"Verifier lifetime must be between 60 and {maximum} seconds.");
        var context = await AuthorizedContextAsync(cancellationToken).ConfigureAwait(false);
        if (context is null) return Denied<IdentityVerificationInitiation>();
        var subject = await store.FindVerificationSubjectAsync(email, cancellationToken).ConfigureAwait(false);
        subject = await ReleaseExpiredLoginLockAsync(subject, request.Purpose, cancellationToken).ConfigureAwait(false);
        if (subject is null || !IsEligible(subject, request.Purpose)) return Ok(new IdentityVerificationInitiation(true));
        var prepared = proofs.Create(new(application.ApplicationId, subject.Identity.UserId, PurposeCode(request.Purpose), subject.Email,
            ContextHash(subject, request.Purpose, request.ProofKind, context, request.Context), validity,
            request.ProofKind == VerificationProofKind.OpaqueToken ? validity : null));
        if (!await store.CreateVerificationChallengeAsync(prepared.Challenge, cancellationToken).ConfigureAwait(false))
            return Ok(new IdentityVerificationInitiation(true));
        return Ok(new IdentityVerificationInitiation(true, new(prepared.Challenge.ChallengeId, request.Purpose, request.ProofKind,
            subject.Email, request.ProofKind == VerificationProofKind.OpaqueToken ? prepared.Token! : prepared.Code,
            prepared.Challenge.ExpiresAt, prepared.ResendAllowedAt)));
    }

    public async ValueTask<IFeedback<IdentityVerificationCompletion>> CompleteAsync(CompleteIdentityVerificationRequest request, CancellationToken cancellationToken = default)
    {
        if (request.ChallengeId == Guid.Empty || !Enum.IsDefined(request.Purpose) || !Enum.IsDefined(request.ProofKind) ||
            string.IsNullOrWhiteSpace(request.Verifier) || request.Verifier.Length > 1000 || request.Context?.Length > 1000 ||
            request.NewPassword is not null && request.Purpose is not (VerificationPurpose.PasswordReset or VerificationPurpose.Onboarding) ||
            request.Purpose != VerificationPurpose.PasswordlessLogin && (request.MfaKind is not null || request.MfaMethodId is not null || request.MfaCode is not null))
            return Fail<IdentityVerificationCompletion>("invalid_request", "The verification completion payload is invalid.");
        if (request.Purpose == VerificationPurpose.PasswordReset || request.NewPassword is not null)
        {
            try { IdentityPolicy.ValidateNewPassword(request.NewPassword!); }
            catch (ArgumentException exception) { return Fail<IdentityVerificationCompletion>("invalid_password", exception.Message); }
        }
        var context = await AuthorizedContextAsync(cancellationToken).ConfigureAwait(false);
        if (context is null) return Denied<IdentityVerificationCompletion>();
        var challenge = await store.FindVerificationChallengeAsync(request.ChallengeId, cancellationToken).ConfigureAwait(false);
        var now = clock.UtcNow;
        if (challenge?.SubjectId is null || challenge.DestinationHash is null ||
            challenge.ApplicationId != application.ApplicationId || challenge.Purpose != PurposeCode(request.Purpose) ||
            !VerificationProofService.IsPending(challenge, now)) return Invalid();
        var subject = await store.FindVerificationSubjectAsync(challenge.SubjectId.Value, challenge.DestinationHash, cancellationToken).ConfigureAwait(false);
        subject = await ReleaseExpiredLoginLockAsync(subject, request.Purpose, cancellationToken).ConfigureAwait(false);
        if (subject is null || !IsEligible(subject, request.Purpose) ||
            !VerificationProofService.Matches(challenge, application.ApplicationId, PurposeCode(request.Purpose),
                ContextHash(subject, request.Purpose, request.ProofKind, context, request.Context), now)) return Invalid();
        if (!proofs.Verify(challenge, request.ProofKind == VerificationProofKind.NumericCode ? request.Verifier : null,
            request.ProofKind == VerificationProofKind.OpaqueToken ? request.Verifier : null, now))
        {
            await store.CompletePasswordlessVerificationAsync(new(challenge.LocalChallengeId, false, challenge.Attempts, null, null, now), cancellationToken).ConfigureAwait(false);
            if (request.Purpose == VerificationPurpose.PasswordlessLogin)
                await RecordAttemptAsync(subject, challenge, "invalid_credential", "passwordless_proof_rejected", cancellationToken).ConfigureAwait(false);
            return challenge.Attempts + 1 >= challenge.MaximumAttempts
                ? Fail<IdentityVerificationCompletion>("verification_exhausted", "The verifier attempt limit was reached.") : Invalid();
        }

        StartOpaqueSessionCommand? sessionCommand = null;
        OpaqueSession? session = null;
        if (request.Purpose == VerificationPurpose.PasswordlessLogin)
        {
            var factors = await mfa.VerifyAsync(new(subject.Identity.UserId, subject.Email, application.ApplicationId, context,
                request.MfaKind, request.MfaMethodId, request.MfaCode), cancellationToken).ConfigureAwait(false);
            if (!factors.Status)
            {
                if (factors.Key == "mfa_invalid")
                    await RecordAttemptAsync(subject, challenge, "invalid_credential", "mfa_invalid", cancellationToken).ConfigureAwait(false);
                return Fail<IdentityVerificationCompletion>(factors.Key ?? "mfa_invalid", factors.Message ?? "Second factor rejected.", 401);
            }
            var token = tokens.Generate();
            session = new(uuids.NewUuid7(), token.Value, clock.UtcNow.AddSeconds(options.Value.SessionSeconds));
            var account = new EnsureAccountCommand(subject.Identity.UserId, Guid.Empty, application.ApplicationId, string.Empty, string.Empty, null, clock.UtcNow);
            sessionCommand = new(account, false, session.SessionId, token.Hash, session.ExpiresAt,
                [request.ProofKind == VerificationProofKind.NumericCode ? "email_otp" : "email_link", .. factors.Result ?? []],
                AuthenticatedUserId: subject.Identity.UserId, OwnerContext: application.OwnerContext);
        }
        SetCredentialCommand? password = request.NewPassword is null ? null :
            new(subject.Identity.UserId, uuids.NewUuid7(), hasher.Hash(request.NewPassword), false, clock.UtcNow);
        if (request.Purpose == VerificationPurpose.Onboarding && subject.Identity.PasswordChangeRequired && password is null)
            return Fail<IdentityVerificationCompletion>("password_required", "This account requires an initial password to finish onboarding.");
        var completed = await store.CompleteIdentityVerificationAsync(new(challenge, subject, request.Purpose, clock.UtcNow, password, sessionCommand),
            previous => request.NewPassword is not null && hasher.Verify(request.NewPassword, previous.Value, previous.Algorithm, previous.ParametersPayload),
            cancellationToken).ConfigureAwait(false);
        if (!completed) return Fail<IdentityVerificationCompletion>("verification_action_rejected",
            "The verifier or account changed, the session was rejected, or the password was used recently.");
        if (session is not null) await RecordAttemptAsync(subject, challenge, "success", null, cancellationToken).ConfigureAwait(false);
        return Ok(new IdentityVerificationCompletion(subject.Identity.UserId, request.Purpose,
            subject.VerifiedAt is not null || request.Purpose is VerificationPurpose.EmailVerification or VerificationPurpose.Onboarding,
            request.Purpose == VerificationPurpose.Onboarding ? IdentityStatus.Active : subject.Identity.Status, session));
    }

    private async ValueTask<StoredVerificationSubject?> ReleaseExpiredLoginLockAsync(StoredVerificationSubject? subject,
        VerificationPurpose purpose, CancellationToken cancellationToken)
    {
        if (purpose == VerificationPurpose.PasswordlessLogin && subject?.Identity.Status == IdentityStatus.Locked &&
            await store.ReleaseExpiredLoginProtectionAsync(subject.Identity.UserId, clock.UtcNow, cancellationToken).ConfigureAwait(false))
            return await store.FindVerificationSubjectAsync(subject.Email, cancellationToken).ConfigureAwait(false);
        return subject;
    }

    private byte[] ContextHash(StoredVerificationSubject subject, VerificationPurpose purpose, VerificationProofKind kind, string ownerContext, string? context) =>
        VerificationProofService.Hash(JsonSerializer.Serialize(new object?[] { "identity.verification.v1", application.ApplicationId,
            ownerContext, purpose, kind, subject.Identity.UserId, subject.ContactId, subject.Email, context,
            purpose == VerificationPurpose.EmailVerification ? null : subject.CredentialId }));

    private async ValueTask<string?> AuthorizedContextAsync(CancellationToken cancellationToken)
    {
        if (application.ApplicationId == Guid.Empty || !authorization.TryNormalizeContext(application.OwnerContext ?? "haley.identity", out var context)) return null;
        return await authorization.HasActiveResourceAuthorityAsync(application.ApplicationId, context, cancellationToken).ConfigureAwait(false) ? context : null;
    }
    private async ValueTask RecordAttemptAsync(StoredVerificationSubject subject, StoredVerificationChallenge challenge, string outcome, string? reason, CancellationToken cancellationToken) =>
        _ = await store.RecordLoginAttemptAndApplyProtectionAsync(new(subject.Identity.UserId, VerificationProofService.Hash(challenge.ChallengeId.ToString("N")),
            application.ApplicationId, outcome, reason, null, null, clock.UtcNow), options.Value.MaximumFailedAttempts,
            options.Value.LockoutSeconds, cancellationToken).ConfigureAwait(false);
    private static IFeedback<IdentityVerificationCompletion> Invalid() => Fail<IdentityVerificationCompletion>("verification_invalid", "The verifier is invalid, expired, consumed, or does not match this request.");
    private static IFeedback<T> Denied<T>() => Fail<T>("invalid_client_resource", "The application is not authorized for this identity context.", 403);
    private static IFeedback<T> Ok<T>(T result) => new Feedback<T>(true, "Identity verification operation completed.", result) { Source = "Haley.Identity" };
    private static IFeedback<T> Fail<T>(string key, string message, int code = 400) => new Feedback<T>(false, message) { Key = key, Code = code, Source = "Haley.Identity" };
}
