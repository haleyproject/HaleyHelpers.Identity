using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;

/// <summary>Account details available only to the application that owns a live opaque session.</summary>
public sealed record ResolvedIdentitySession(
    Guid SessionId, DateTimeOffset ExpiresAt, Guid UserId, string DisplayName, string? Email,
    bool EmailVerified,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus Status,
    IReadOnlyCollection<string> AuthenticationMethods);
