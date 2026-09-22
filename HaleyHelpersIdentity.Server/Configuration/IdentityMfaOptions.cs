namespace Haley.Models;

public sealed class IdentityMfaOptions
{
    public int EnrollmentSeconds { get; set; } = 600;
    public int MaximumEnrollmentAttempts { get; set; } = 5;
    public int RecoveryCodeCount { get; set; } = 10;
}
