namespace Haley.Models;
public sealed class IdentityVerificationOptions
{
    /// <summary>Maximum lifetime for manually entered codes. Long-lived invitations should use opaque tokens.</summary>
    public int MaximumCodeValiditySeconds { get; set; } = 3_600;
    /// <summary>Maximum opaque-token lifetime. Applications may request e.g. 259200 seconds (three days).</summary>
    public int MaximumTokenValiditySeconds { get; set; } = 604_800;
    public int CodeLength { get; set; } = 6;
    public int CodeValiditySeconds { get; set; } = 300;
    public int ResendDelaySeconds { get; set; } = 300;
    public int MaximumAttempts { get; set; } = 5;
    public int ExhaustedCooldownSeconds { get; set; } = 900;
    public int ActivationLinkSeconds { get; set; } = 86_400;
    public int PasswordResetSeconds { get; set; } = 1_800;
    public int LinkProofSeconds { get; set; } = 900;
}
