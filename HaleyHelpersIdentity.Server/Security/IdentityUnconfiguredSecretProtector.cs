using Haley.Security;

namespace Haley.Security;

public sealed class IdentityUnconfiguredSecretProtector : ISecretEnvelopeProtector
{
    public byte[] Protect(ReadOnlySpan<byte> value, string purpose) => throw new InvalidOperationException("Identity MFA secret protection is not configured.");
    public byte[] Unprotect(ReadOnlySpan<byte> value, string purpose) => throw new InvalidOperationException("Identity MFA secret protection is not configured.");
}
