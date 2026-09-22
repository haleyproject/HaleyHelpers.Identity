namespace Haley.Models;

public sealed record StoredPasswordResetSubject(
    Guid UserId,
    IdentityStatus Status,
    string Channel,
    string DestinationNormalized,
    string DestinationDisplay);
