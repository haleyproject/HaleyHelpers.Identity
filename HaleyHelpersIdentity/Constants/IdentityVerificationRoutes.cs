namespace Haley.Constants;

/// <summary>Purpose-specific routes let remote owners apply distinct permissions to each action.</summary>
public static class IdentityVerificationRoutes
{
    public static string Segment(VerificationPurpose purpose) => purpose switch
    {
        VerificationPurpose.EmailVerification => "email",
        VerificationPurpose.Onboarding => "onboarding",
        VerificationPurpose.PasswordReset => "password-reset",
        VerificationPurpose.PasswordlessLogin => "login",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose))
    };
    public static string Operation(VerificationPurpose purpose, bool complete) =>
        (complete ? "Complete" : "Begin") + "Verification" + purpose;
}
