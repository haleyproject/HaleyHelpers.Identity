using System.Text.Json;

namespace Haley.Security;

internal static class ProviderApplicationPolicy
{
    internal static bool Allows(string configuration, Guid applicationId, bool requireAllowlist = false)
    {
        try
        {
            using var document = JsonDocument.Parse(configuration);
            if (!document.RootElement.TryGetProperty("allowedApplicationIds", out var allowed)) return !requireAllowlist;
            if (allowed.ValueKind != JsonValueKind.Array) return false;
            var entries = allowed.EnumerateArray().ToArray();
            return (entries.Length == 0 && !requireAllowlist) || entries.Any(item => item.ValueKind == JsonValueKind.String &&
                Guid.TryParse(item.GetString(), out var id) && id == applicationId);
        }
        catch (JsonException) { return false; }
    }
}
