namespace Haley.Models;
public sealed record StoredUserCredential(long LocalUserId, long LocalCredentialId, Guid UserId, string DisplayName, IdentityStatus Status, string? Username, DateTimeOffset CreatedAt, DateTimeOffset? LastAuthenticatedAt, byte[] SecretHash, string Algorithm, string? ParametersPayload, bool PasswordChangeRequired);
