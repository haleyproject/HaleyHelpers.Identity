namespace Haley.Models;
public sealed record CreateLocalUserCommand(Guid UserId, Guid CredentialId, string UsernameNormalized, string DisplayName, IdentityStatus Status, byte[] SecretHash, string Algorithm, string ParametersPayload, bool RequirePasswordChange, DateTimeOffset CreatedAt, Guid? EmailContactId = null);
