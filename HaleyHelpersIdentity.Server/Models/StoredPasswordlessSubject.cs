namespace Haley.Models;

public sealed record StoredPasswordlessSubject(
    long LocalUserId,
    UserIdentity Identity,
    string DestinationNormalized,
    string DestinationDisplay);
