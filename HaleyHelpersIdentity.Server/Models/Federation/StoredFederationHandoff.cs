namespace Haley.Models;
public sealed record StoredFederationHandoff(Guid HandoffId, Guid ApplicationId, string Context, byte[] PayloadEncrypted, byte[] CodeChallenge, DateTimeOffset ExpiresAt);
