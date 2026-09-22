namespace Haley.Security;

internal sealed record PasswordParameters(int Iterations, int SaltBytes, int SubkeyBytes, string Prf);
