using System.Text.Json;

namespace Haley.Security;

internal static class ProviderApplicationPolicy
{
    internal static bool Allows(string configuration, Guid applicationId, bool requireAllowlist = false)
    {
        try
        {
            using var document = JsonDocument.Parse(configuration);
            var allowed = ReadIds(document.RootElement, "allowedApplicationIds");
            ValidateDefaults(allowed, ReadIds(document.RootElement, "defaultForApplicationIds"));
            return applicationId != Guid.Empty && ((allowed.Count == 0 && !requireAllowlist) || allowed.Contains(applicationId));
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException) { return false; }
    }

    internal static IReadOnlySet<Guid> DefaultApplications(string configuration)
    {
        using var document = JsonDocument.Parse(configuration);
        var allowed = ReadIds(document.RootElement, "allowedApplicationIds");
        var defaults = ReadIds(document.RootElement, "defaultForApplicationIds");
        ValidateDefaults(allowed, defaults);
        return defaults;
    }

    private static HashSet<Guid> ReadIds(JsonElement root, string name)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidOperationException("Provider configuration must be an object.");
        if (!root.TryGetProperty(name, out var values)) return [];
        if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() > 512)
            throw new InvalidOperationException($"'{name}' must contain at most 512 application UUIDs.");
        var ids = new HashSet<Guid>();
        foreach (var value in values.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String || !Guid.TryParse(value.GetString(), out var id) || id == Guid.Empty)
                throw new InvalidOperationException($"'{name}' contains an invalid application UUID.");
            ids.Add(id);
        }
        return ids;
    }

    private static void ValidateDefaults(HashSet<Guid> allowed, HashSet<Guid> defaults)
    {
        if (allowed.Count > 0 && !defaults.IsSubsetOf(allowed))
            throw new InvalidOperationException("Default applications must also be allowed to use this provider.");
    }
}
