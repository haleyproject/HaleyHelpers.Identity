namespace Haley.Models;

/// <summary>Primary authenticator login. The email identifies an account; it is not an authentication factor.</summary>
public sealed record TotpAuthenticationRequest(string Email, string Code,
    Guid? MethodId = null, MfaKind Kind = MfaKind.Totp);
