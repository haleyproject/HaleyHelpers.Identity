namespace Haley.Models;

public sealed record SetCredentialCommand(Guid UserId, Guid CredentialId, PasswordHash Password,
    bool RequirePasswordChange, DateTimeOffset ChangedAt, long? ExpectedCredentialId = null);
