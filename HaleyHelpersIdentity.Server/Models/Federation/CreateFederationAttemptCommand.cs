namespace Haley.Models;
public sealed record CreateFederationAttemptCommand(Guid RequestId, long LocalProviderId, Guid ApplicationId, string Context, string ProtocolRequestId, string ReturnUri, string State, byte[] CodeChallenge, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);
