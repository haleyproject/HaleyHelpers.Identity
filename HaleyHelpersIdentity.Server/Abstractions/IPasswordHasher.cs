namespace Haley.Abstractions;

public interface IPasswordHasher
{
    PasswordHash Hash(string password);
    bool Verify(string password, byte[] expectedHash, string algorithm, string? parametersPayload);
}
