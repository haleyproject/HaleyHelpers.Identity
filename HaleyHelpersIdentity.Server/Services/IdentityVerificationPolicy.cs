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

    internal static bool IsEligible(StoredVerificationSubject subject, VerificationPurpose purpose) => purpose switch
    {
        VerificationPurpose.EmailVerification => subject.Identity.Status is IdentityStatus.Pending or IdentityStatus.Active,
        VerificationPurpose.Onboarding => subject.Identity.Status == IdentityStatus.Pending,
        VerificationPurpose.PasswordReset => subject.Identity.Status == IdentityStatus.Active &&
            subject.VerifiedAt is not null && subject.RecoveryEnabled && subject.CredentialId is not null,
        VerificationPurpose.PasswordlessLogin => subject.Identity.Status == IdentityStatus.Active &&
            subject.VerifiedAt is not null && subject.RecoveryEnabled && !subject.Identity.PasswordChangeRequired,
        _ => false
    };
}
