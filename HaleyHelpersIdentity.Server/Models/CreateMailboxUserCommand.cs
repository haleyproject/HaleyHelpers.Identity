namespace Haley.Models;
public sealed record CreateMailboxUserCommand(Guid UserId, Guid ContactId, string EmailNormalized, string EmailDisplay, string DisplayName, IdentityStatus Status, uint Flags, DateTimeOffset CreatedAt, Guid? OriginClientId = null, string? Origin = null, byte[]? SourceHash = null);
