using Haley.Abstractions;

namespace Haley.Models;
public enum MfaKind
{
    EmailOtp,
    Saml,
    Totp,
    RecoveryCode
}
