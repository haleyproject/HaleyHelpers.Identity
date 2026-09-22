namespace Haley.Models;

public sealed record PasswordHash(byte[] Value, string Algorithm, string ParametersPayload);
