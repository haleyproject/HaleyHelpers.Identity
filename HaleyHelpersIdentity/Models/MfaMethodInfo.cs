using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record MfaMethodInfo(Guid MethodId, Guid UserId, MfaKind Kind, string? Label, [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityRecordStatus>))] IdentityRecordStatus Status, DateTimeOffset CreatedAt, DateTimeOffset? VerifiedAt, DateTimeOffset? LastUsedAt);
