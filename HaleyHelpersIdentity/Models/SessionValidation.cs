namespace Haley.Models;

/// <summary>Session validation deliberately does not disclose account claims.</summary>
public sealed record SessionValidation(Guid SessionId, DateTimeOffset ExpiresAt);
