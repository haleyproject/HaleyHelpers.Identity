using System.Text.Json.Serialization;

namespace Haley.Models;

public sealed record AccountSessionInfo(Guid SessionId, Guid UserId, Guid? ApplicationId,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityRecordStatus>))] IdentityRecordStatus Status,
    DateTimeOffset AuthenticatedAt, DateTimeOffset LastSeenAt, DateTimeOffset ExpiresAt, DateTimeOffset? EndedAt);
