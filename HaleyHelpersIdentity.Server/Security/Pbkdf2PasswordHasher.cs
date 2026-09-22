using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Haley.Security;
public sealed class Pbkdf2PasswordHasher(IOptions<IdentityServerOptions> options) : IPasswordHasher
{
    private const string AlgorithmName = "pbkdf2-sha512";
    private const int SaltLength = 16;
    private const int SubkeyLength = 32;
    public PasswordHash Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var iterations = Math.Max(100_000, options.Value.PasswordHashIterations);
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var subkey = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA512, SubkeyLength);
        var value = new byte[SaltLength + SubkeyLength];
        salt.CopyTo(value, 0);
        subkey.CopyTo(value, SaltLength);
        var parameters = JsonSerializer.Serialize(new PasswordParameters(iterations, SaltLength, SubkeyLength, "HMACSHA512"));
        return new(value, AlgorithmName, parameters);
    }

    public bool Verify(string password, byte[] expectedHash, string algorithm, string? parametersPayload)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(expectedHash);
        if (!string.Equals(algorithm, AlgorithmName, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(parametersPayload))
        {
            return false;
        }

        PasswordParameters? parameters;
        try
        {
            parameters = JsonSerializer.Deserialize<PasswordParameters>(parametersPayload);
        }
        catch (JsonException)
        {
            return false;
        }

        if (parameters is null || parameters.Iterations < 100_000 || parameters.SaltBytes != SaltLength || parameters.SubkeyBytes != SubkeyLength || expectedHash.Length != SaltLength + SubkeyLength || !string.Equals(parameters.Prf, "HMACSHA512", StringComparison.Ordinal))
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), expectedHash.AsSpan(0, SaltLength), parameters.Iterations, HashAlgorithmName.SHA512, SubkeyLength);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash.AsSpan(SaltLength, SubkeyLength));
    }

}
