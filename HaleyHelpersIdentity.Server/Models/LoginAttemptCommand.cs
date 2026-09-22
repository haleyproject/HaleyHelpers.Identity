namespace Haley.Models;
public sealed record LoginAttemptCommand(Guid? UserId, byte[] LoginHintHash, Guid? ApplicationId, string Outcome, string? ReasonCode, byte[]? IpHash, byte[]? UserAgentHash, DateTimeOffset OccurredAt);
