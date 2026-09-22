using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Haley.Security;
public sealed class SecretTokenGenerator : ISecretTokenGenerator
{
    public SecretToken Generate()
    {
        var value = Base64Url(RandomNumberGenerator.GetBytes(64));
        return new(value, Hash(value));
    }

    public byte[] Hash(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return SHA256.HashData(Encoding.UTF8.GetBytes(token));
    }

    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
