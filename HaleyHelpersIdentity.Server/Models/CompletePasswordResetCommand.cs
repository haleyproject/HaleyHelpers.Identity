namespace Haley.Models;

public sealed record CompletePasswordResetCommand(
    Guid GrantId,
    Guid ApplicationId,
    byte[] ContextHash,
    Guid CurrentCredentialId,
    Guid CredentialId,
    byte[] SecretHash,
    string Algorithm,
    string ParametersPayload,
    DateTimeOffset CompletedAt);
