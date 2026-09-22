using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record ChangeUserStatusRequest(Guid UserId, [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus Status, string ReasonCode);
