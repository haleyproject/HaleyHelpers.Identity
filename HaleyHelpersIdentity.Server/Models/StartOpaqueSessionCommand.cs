namespace Haley.Models;

public sealed record StartOpaqueSessionCommand(EnsureAccountCommand Account, bool CreateIfMissing,
    Guid SessionId, byte[] TokenHash, DateTimeOffset ExpiresAt, IReadOnlyCollection<string> AuthenticationMethods,
    long? ExpectedCredentialId = null, Guid? AuthenticatedUserId = null, string? OwnerContext = null);
