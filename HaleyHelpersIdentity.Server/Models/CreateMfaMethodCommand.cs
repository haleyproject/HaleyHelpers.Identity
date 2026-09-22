namespace Haley.Models;
public sealed record CreateMfaMethodCommand(Guid MethodId, Guid UserId, MfaKind Kind, string? Label, byte[]? SecretEncrypted, string? PublicData, DateTimeOffset CreatedAt);
