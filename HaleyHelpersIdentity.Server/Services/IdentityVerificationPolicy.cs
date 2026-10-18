namespace Haley.Services;

internal static class IdentityVerificationPolicy
{
    internal static string PurposeCode(VerificationPurpose purpose) => purpose switch
    {
        VerificationPurpose.EmailVerification => "identity.email.verify",
        VerificationPurpose.Onboarding => "identity.onboard",
        VerificationPurpose.PasswordReset => "identity.password.reset.direct",
        VerificationPurpose.PasswordlessLogin => "identity.passwordless.login",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose))
    };

    internal static bool IsEligible(StoredVerificationSubject subject, VerificationPurpose purpose) =>
        IneligibilityReason(subject, purpose) is null;

    internal static string? IneligibilityReason(StoredVerificationSubject subject, VerificationPurpose purpose)
    {
        var status = subject.Identity.Status;
        if (purpose == VerificationPurpose.EmailVerification)
            return status is IdentityStatus.Pending or IdentityStatus.Active ? null :
                $"Email verification requires a Pending or Active account. This account is {status}.";
        if (purpose == VerificationPurpose.Onboarding)
            return status == IdentityStatus.Pending ? null :
                $"Onboarding requires a Pending account. This account is {status}. To repeat mailbox verification, choose Verify email.";
        if (purpose is not (VerificationPurpose.PasswordReset or VerificationPurpose.PasswordlessLogin))
            return "Select a supported verification purpose.";
        if (status != IdentityStatus.Active)
            return $"This operation requires an Active account. This account is {status}. Verifying an email does not activate the account; complete onboarding or change its lifecycle state.";
        if (subject.VerifiedAt is null)
            return "Verify this email first, using an email challenge or the administrator's break-glass action.";
        if (!subject.RecoveryEnabled)
            return "This email is verified but recovery is disabled. Use Break-glass verify to confirm ownership and enable recovery.";
        if (purpose == VerificationPurpose.PasswordReset && subject.CredentialId is null)
            return "Password recovery requires an existing password. This account has no active password; set an initial password in the account's lifecycle controls.";
        if (purpose == VerificationPurpose.PasswordlessLogin && subject.Identity.PasswordChangeRequired)
            return "This account requires a password change. Set or recover its password before passwordless sign-in.";
        return null;
    }
}
