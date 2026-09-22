using System.Text;
namespace Haley.Utils;

public static class IdentityPolicy
{
    public const uint HumanIdentityFlag = 1;
    public const uint PasswordChangeRequiredFlag = 2;
    public const int MinimumPasswordLength = 9;
    public const int MaximumPasswordLength = 1024;
    public const int MaximumUsernameLength = 190;

    public static string NormalizeUsername(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        var normalized = username.Trim().Normalize().ToLowerInvariant();
        if (normalized.Length > MaximumUsernameLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(username),
                $"A login identifier cannot exceed {MaximumUsernameLength} characters.");
        }

        if (normalized.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException(
                "A login identifier cannot contain whitespace or control characters.",
                nameof(username));
        }

        return normalized;
    }

    public static bool TryNormalizeUsername(string? username, out string normalized)
    {
        try
        {
            normalized = NormalizeUsername(username!);
            return true;
        }
        catch (ArgumentException)
        {
            normalized = string.Empty;
            return false;
        }
    }

    public static bool TryNormalizeEmail(string? value, out string normalized)
    {
        if (!TryNormalizeUsername(value, out normalized))
        {
            return false;
        }

        var separator = normalized.IndexOf('@');
        return separator > 0 && separator == normalized.LastIndexOf('@') && separator < normalized.Length - 1;
    }

    public static string NormalizeDisplayName(string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        var normalized = CollapseWhitespace(displayName);
        if (normalized.Length > 250)
        {
            throw new ArgumentOutOfRangeException(nameof(displayName), "Display name cannot exceed 250 characters.");
        }

        return normalized;
    }

    public static string? NormalizeOptionalName(string? value, int maximumLength = 150)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = CollapseWhitespace(value);
        if (normalized.Length > maximumLength)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"Value cannot exceed {maximumLength} characters.");
        }

        return normalized;
    }

    public static string? NormalizeOptionalValue(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().Normalize();

    public static void ValidateDisplayName(string displayName)
    {
        _ = NormalizeDisplayName(displayName);
    }

    public static void ValidateNewPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length is < MinimumPasswordLength or > MaximumPasswordLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(password),
                $"Password length must be between {MinimumPasswordLength} and {MaximumPasswordLength} characters.");
        }
    }

    public static void ValidateProfile(UpdateUserProfileRequest profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ValidateDisplayName(profile.DisplayName);
        _ = NormalizeOptionalName(profile.GivenName);
        _ = NormalizeOptionalName(profile.FamilyName);
        _ = NormalizeOptionalName(profile.PreferredName);
        ValidateOptional(profile.Locale, 20, nameof(profile.Locale));
        ValidateOptional(profile.TimeZone, 64, nameof(profile.TimeZone));
        ValidateOptional(profile.AvatarUri, 1000, nameof(profile.AvatarUri));

        if (!string.IsNullOrWhiteSpace(profile.AvatarUri) &&
            (!Uri.TryCreate(profile.AvatarUri.Trim(), UriKind.Absolute, out var avatar) ||
             (avatar.Scheme != Uri.UriSchemeHttps && avatar.Scheme != Uri.UriSchemeHttp)))
        {
            throw new ArgumentException("Avatar URI must be an absolute HTTP or HTTPS URI.", nameof(profile.AvatarUri));
        }
    }

    public static bool CanAuthenticate(IdentityStatus status) => status == IdentityStatus.Active;

    private static void ValidateOptional(string? value, int maximumLength, string parameterName)
    {
        if (value?.Trim().Length > maximumLength)
        {
            throw new ArgumentOutOfRangeException(parameterName, $"Value cannot exceed {maximumLength} characters.");
        }
    }

    private static string CollapseWhitespace(string value)
    {
        var source = value.Normalize();
        var result = new StringBuilder(source.Length);
        var pendingSpace = false;
        foreach (var character in source)
        {
            if (char.IsWhiteSpace(character))
            {
                pendingSpace = result.Length > 0;
                continue;
            }

            if (char.IsControl(character))
            {
                throw new ArgumentException("Display text cannot contain control characters.", nameof(value));
            }

            if (pendingSpace)
            {
                result.Append(' ');
                pendingSpace = false;
            }
            result.Append(character);
        }

        return result.ToString();
    }
}
