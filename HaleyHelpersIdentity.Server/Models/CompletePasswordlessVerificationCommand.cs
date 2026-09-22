namespace Haley.Models;

public sealed record CompletePasswordlessVerificationCommand(
    long LocalChallengeId,
    bool Succeeded,
    int ExpectedAttempts,
    byte[]? IpHash,
    byte[]? UserAgentHash,
    DateTimeOffset OccurredAt);
