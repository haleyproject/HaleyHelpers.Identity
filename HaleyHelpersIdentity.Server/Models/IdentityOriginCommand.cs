namespace Haley.Models;
public sealed record IdentityOriginCommand(Guid UserId, Guid ApplicationId, string Origin, byte[] SourceHash, DateTimeOffset CreatedAt);
