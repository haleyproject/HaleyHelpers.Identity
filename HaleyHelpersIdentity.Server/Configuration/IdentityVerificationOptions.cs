namespace Haley.Models;
public sealed class IdentityVerificationOptions
{
    public int CodeLength { get; set; } = 6;
    public int CodeValiditySeconds { get; set; } = 300;
    public int ResendDelaySeconds { get; set; } = 300;
    public int MaximumAttempts { get; set; } = 5;
    public int ExhaustedCooldownSeconds { get; set; } = 900;
    public int ActivationLinkSeconds { get; set; } = 86_400;
    public int PasswordResetSeconds { get; set; } = 1_800;
    public int LinkProofSeconds { get; set; } = 900;
}
