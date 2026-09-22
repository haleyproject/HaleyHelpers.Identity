namespace Haley.Models;

public sealed record CreateMfaEnrollmentCommand(
    Guid MethodId,
    Guid UserId,
    string Label,
    byte[] SecretEncrypted,
    string PublicData,
    byte[] TicketHash,
    Guid? ApplicationId,
    string? Audience,
    string? ReturnUri,
    Guid? ReplaceMethodId,
    int MaximumAttempts,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt);
