using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using Haley.Abstractions;
using Haley.Models;
using Haley.Security;
using Haley.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Haley.Security;
internal sealed class SamlProviderConfiguration
{
    public required Uri SsoUrl { get; init; }
    public required Uri AcsUrl { get; init; }
    public required string SpEntityId { get; init; }
    public required string[] SigningCertificates { get; init; }
    public string? EmailClaim { get; init; }
    public string? DisplayNameClaim { get; init; }
    public SamlAssertionValidationOptions Validation { get; init; } = new();

    public static SamlProviderConfiguration Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var result = new SamlProviderConfiguration
        {
            SsoUrl = Absolute(root, "ssoUrl"),
            AcsUrl = Absolute(root, "acsUrl"),
            SpEntityId = Required(root, "spEntityId"),
            SigningCertificates = ParseCertificateNames(root),
            EmailClaim = Optional(root, "emailClaim"),
            DisplayNameClaim = Optional(root, "displayNameClaim"),
            Validation = ParseValidation(root)
        };
        if (result.SigningCertificates.Length == 0)
            throw new InvalidOperationException("SAML signing certificates are required.");
        if (result.Validation.AllowUnsafeValidation || !result.Validation.ValidateSignature || !result.Validation.ValidateIssuer ||
            !result.Validation.ValidateAudience || !result.Validation.ValidateLifetime || !result.Validation.ValidateDestination ||
            !result.Validation.ValidateRecipient || !result.Validation.ValidateInResponseTo || !result.Validation.ValidateReplay || result.Validation.ClockSkew < TimeSpan.Zero || result.Validation.ClockSkew > TimeSpan.FromMinutes(2))
            throw new InvalidOperationException("Unsafe SAML validation is not accepted.");
        result.Validation.ValidateConfiguration();
        return result;
    }

    public IReadOnlyCollection<X509Certificate2> LoadCertificates(IIdentitySamlCertificateService certificates) =>
        certificates.LoadCertificates(SigningCertificates);

    private static string[] ParseCertificateNames(JsonElement root)
    {
        if (!root.TryGetProperty("signingCertificates", out var certificates) ||
            certificates.ValueKind != JsonValueKind.Array)
            return [];
        var result = new List<string>();
        foreach (var item in certificates.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String ||
                !SamlCertificateNames.TryNormalize(item.GetString(), out var name))
                throw new InvalidOperationException("SAML signing certificates must use managed certificate names.");
            result.Add(name);
        }
        return result.Distinct(StringComparer.Ordinal).ToArray();
    }
    private static SamlAssertionValidationOptions ParseValidation(JsonElement root)
    {
        var result = new SamlAssertionValidationOptions();
        if (!root.TryGetProperty("validation", out var value) || value.ValueKind != JsonValueKind.Object)
            return result;
        result.ValidateSignature = Bool(value, "validateSignature", true);
        result.ValidateIssuer = Bool(value, "validateIssuer", true);
        result.ValidateAudience = Bool(value, "validateAudience", true);
        result.ValidateLifetime = Bool(value, "validateLifetime", true);
        result.ValidateDestination = Bool(value, "validateDestination", true);
        result.ValidateRecipient = Bool(value, "validateRecipient", true);
        result.ValidateInResponseTo = Bool(value, "validateInResponseTo", true);
        result.ValidateReplay = Bool(value, "validateReplay", true);
        result.AllowUnsafeValidation = Bool(value, "allowUnsafeValidation", false);
        if (value.TryGetProperty("clockSkewSeconds", out var skew) && skew.TryGetInt32(out var seconds))
            result.ClockSkew = TimeSpan.FromSeconds(seconds);
        return result;
    }

    private static Uri Absolute(JsonElement root, string name)
    {
        var value = Required(root, name);
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo))
            throw new UriFormatException($"SAML provider '{name}' must use HTTPS, or loopback HTTP for development.");
        return uri;
    }

    private static string Required(JsonElement root, string name) => root.TryGetProperty(name, out var value) && !string.IsNullOrWhiteSpace(value.GetString()) ? value.GetString()!.Trim() : throw new InvalidOperationException($"SAML provider '{name}' is required.");
    private static string? Optional(JsonElement root, string name) => root.TryGetProperty(name, out var value) ? value.GetString()?.Trim() : null;
    private static bool Bool(JsonElement root, string name, bool fallback) => root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : fallback;
}
