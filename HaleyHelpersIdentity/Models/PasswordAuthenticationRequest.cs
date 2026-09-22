namespace Haley.Models;

public sealed record PasswordAuthenticationRequest(string Username, string Password,
    Guid? MfaMethodId = null, MfaKind? MfaKind = null, string? MfaCode = null);
