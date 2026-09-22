namespace Haley.Models;
/// <summary>Server persistence command; LocalUserId is never a public API identifier.</summary>
public sealed record CreateSessionCommand(Guid SessionId, long LocalUserId, Guid? ApplicationId, IdentitySessionKind Kind,
    DateTimeOffset ExpiresAt, DateTimeOffset CreatedAt, IReadOnlyCollection<string> AuthenticationMethods,
    byte[]? IpHash = null, byte[]? UserAgentHash = null, byte[]? DeviceHash = null);
