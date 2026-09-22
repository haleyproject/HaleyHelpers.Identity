namespace Haley.Models;
public sealed record StoredMfaMethod(MfaMethodInfo Method, byte[]? SecretEncrypted, string? PublicData);
