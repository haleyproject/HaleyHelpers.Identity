namespace Haley.Models;
public sealed record ChangePasswordCommand(long LocalUserId, long LocalCredentialId, Guid UserId, Guid CredentialId, byte[] SecretHash, string Algorithm, string ParametersPayload, DateTimeOffset ChangedAt);
