using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record UserIdentity(Guid UserId, string DisplayName, [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus Status, string? Username, DateTimeOffset CreatedAt, DateTimeOffset? LastAuthenticatedAt, bool PasswordChangeRequired = false);
