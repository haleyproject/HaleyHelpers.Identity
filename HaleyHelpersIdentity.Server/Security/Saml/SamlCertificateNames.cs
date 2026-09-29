namespace Haley.Security;

internal static class SamlCertificateNames
{
    private const int MaximumNameLength = 120;

    internal static bool TryNormalize(string? value, out string name)
    {
        name = value?.Trim().Normalize().ToLowerInvariant() ?? string.Empty;
        if (name.Length is < 5 or > MaximumNameLength ||
            !name.EndsWith(".cer", StringComparison.Ordinal) &&
            !name.EndsWith(".pem", StringComparison.Ordinal))
        {
            return false;
        }

        if (!char.IsAsciiLetterOrDigit(name[0]) ||
            name.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '_' and not '-'))
        {
            return false;
        }

        return string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal);
    }
}
