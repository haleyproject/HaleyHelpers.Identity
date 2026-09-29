using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Haley.Security;

internal sealed class ExternalProviderConfiguration
{
    public required Uri AuthorizationUrl { get; init; }
    public required Uri CallbackUrl { get; init; }
    public required string Audience { get; init; }
    public required IReadOnlyDictionary<string, string> PublicKeys { get; init; }
    public int MaximumAssertionSeconds { get; init; } = 120;

    public static ExternalProviderConfiguration Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var key in root.GetProperty("keys").EnumerateArray())
        {
            var id = Required(key, "id");
            var pem = Required(key, "pem");
            if (id.Length > 100 || pem.Length > 16384 || pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Only named public RSA keys are accepted.");
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            if (rsa.KeySize < 2048 || !keys.TryAdd(id, pem))
                throw new InvalidOperationException("RSA keys must have unique identifiers and at least 2048 bits.");
        }
        if (keys.Count is < 1 or > 10) throw new InvalidOperationException("Between one and ten public keys are required.");
        var maximum = root.TryGetProperty("maximumAssertionSeconds", out var duration) ? duration.GetInt32() : 120;
        if (maximum is < 30 or > 300) throw new InvalidOperationException("Assertion lifetime must be between 30 and 300 seconds.");
        return new()
        {
            AuthorizationUrl = Absolute(root, "authorizationUrl"), CallbackUrl = Absolute(root, "callbackUrl"),
            Audience = Required(root, "audience"), PublicKeys = keys, MaximumAssertionSeconds = maximum
        };
    }

    public IReadOnlyCollection<SecurityKey> LoadKeys() => PublicKeys.Select(pair =>
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pair.Value);
        return (SecurityKey)new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = pair.Key };
    }).ToArray();

    private static string Required(JsonElement value, string name) =>
        value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString())
            ? item.GetString()!.Trim() : throw new InvalidOperationException($"External provider '{name}' is required.");

    private static Uri Absolute(JsonElement value, string name)
    {
        if (!Uri.TryCreate(Required(value, name), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidOperationException("Provider endpoints require HTTPS, or loopback HTTP for development.");
        return uri;
    }
}
