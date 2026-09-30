namespace Haley.Models;

/// <summary>The bridge contract is independent of the Identity package version.</summary>
public static class SignedCallbackContract
{
    public const int Version1 = 1;
    public const string TokenType = "identity-bridge+jwt";
}
