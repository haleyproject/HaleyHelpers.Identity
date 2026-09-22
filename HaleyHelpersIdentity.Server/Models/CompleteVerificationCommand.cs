namespace Haley.Models;
public sealed record CompleteVerificationCommand(long LocalChallengeId, Guid GrantId, bool Succeeded, int ExpectedAttempts, byte[]? IpHash, byte[]? UserAgentHash, DateTimeOffset OccurredAt, DateTimeOffset GrantExpiresAt);
