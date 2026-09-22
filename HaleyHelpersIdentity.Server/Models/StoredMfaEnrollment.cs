namespace Haley.Models;

public sealed record StoredMfaEnrollment(
    StoredMfaMethod Method,
    int Attempts,
    int MaximumAttempts,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? ConsumedAt,
    string? ReturnUri,
    Guid? ReplaceMethodId);
