namespace Haley.Models;

public sealed record EnsureAccountCommand(Guid UserId, Guid ContactId, Guid ApplicationId,
    string Email, string DisplayName, byte[]? SourceHash, DateTimeOffset CreatedAt);
