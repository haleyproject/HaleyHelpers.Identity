using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Email verification alone does not activate an account. Only passwordless login returns a session.</summary>
public sealed record IdentityVerificationCompletion(Guid UserId,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<VerificationPurpose>))] VerificationPurpose Purpose, bool EmailVerified,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus AccountStatus, OpaqueSession? Session = null);
