namespace Haley.Models;

/// <summary>The token is an opaque bearer secret returned only when a session is created.</summary>
public sealed record OpaqueSession(Guid SessionId, string Token, DateTimeOffset ExpiresAt);
