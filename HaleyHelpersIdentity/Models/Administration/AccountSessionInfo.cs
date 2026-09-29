namespace Haley.Models;

public sealed record AccountSessionInfo(Guid SessionId, Guid UserId, Guid? ApplicationId, IdentityRecordStatus Status,
    DateTimeOffset AuthenticatedAt, DateTimeOffset LastSeenAt, DateTimeOffset ExpiresAt, DateTimeOffset? EndedAt);
