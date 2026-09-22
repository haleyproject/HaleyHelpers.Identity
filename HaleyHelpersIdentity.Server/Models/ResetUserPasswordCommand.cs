namespace Haley.Models;
public sealed record ResetUserPasswordCommand(Guid UserId, Guid CredentialId, byte[] SecretHash, string Algorithm, string ParametersPayload, bool RequirePasswordChange, string ReasonCode, string ActorReference, DateTimeOffset ChangedAt);
