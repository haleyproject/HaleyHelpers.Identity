namespace Haley.Models;
public sealed record CompleteFederationAttemptCommand(long LocalRequestId, Guid HandoffId, byte[] CodeHash, byte[] PayloadEncrypted, DateTimeOffset CompletedAt, DateTimeOffset ExpiresAt);
