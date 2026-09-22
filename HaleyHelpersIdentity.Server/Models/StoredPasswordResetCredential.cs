namespace Haley.Models;

public sealed record StoredPasswordResetCredential(
    Guid CredentialId,
    byte[] SecretHash,
    string Algorithm,
    string? ParametersPayload);
