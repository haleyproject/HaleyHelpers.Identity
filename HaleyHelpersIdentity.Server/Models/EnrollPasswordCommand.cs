namespace Haley.Models;
public sealed record EnrollPasswordCommand(Guid GrantId, Guid ApplicationId, Guid UserId, byte[] ContextHash, Guid CredentialId, byte[] SecretHash, string Algorithm, string ParametersPayload, DateTimeOffset EnrolledAt);
