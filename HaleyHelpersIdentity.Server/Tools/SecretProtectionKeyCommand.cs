using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Security;

namespace Haley.Utils;

/// <summary>Configures an offline host key without replacing existing protected-data keys.</summary>
public static class SecretProtectionKeyCommand
{
    public static async Task<int> RunAsync(string[] args, string toolName, string configurationSection,
        string? settingsPath = null, CancellationToken cancellationToken = default)
    {
        string? keyPath = null;
        var settingsSupplied = settingsPath is not null;
        for (var index = 1; index < args.Length; index++)
        {
            var option = args[index].ToLowerInvariant();
            if (option is "--help" or "-h")
            {
                PrintUsage(toolName);
                return 0;
            }
            if (option is not ("--settings" or "--key-file") || index + 1 >= args.Length ||
                string.IsNullOrWhiteSpace(args[index + 1]) || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                return Invalid(toolName);
            var value = args[++index];
            if (option == "--settings")
            {
                if (settingsSupplied) return Invalid(toolName);
                settingsPath = value;
                settingsSupplied = true;
            }
            else
            {
                if (keyPath is not null) return Invalid(toolName);
                keyPath = Path.GetFullPath(value);
            }
        }

        var selectedPath = Path.GetFullPath(settingsPath ?? Path.Combine(AppContext.BaseDirectory, "appsettings.json"));
        if (!File.Exists(selectedPath))
            throw new FileNotFoundException("The selected appsettings file must exist. Use --settings to select the host configuration.");
        var settings = new IdentitySettingsFile(selectedPath);
        await using var fileLock = await settings.AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var root = IdentitySettingsFile.Parse(settings.ReadContent(requireExisting: true));
        var protection = root;
        foreach (var part in configurationSection.Split(':'))
        {
            if (protection[part] is null) protection[part] = new JsonObject();
            protection = protection[part] as JsonObject
                ?? throw new InvalidDataException($"{configurationSection} must contain JSON objects.");
        }

        var activeId = protection["ActiveKeyId"]?.GetValue<string>();
        var keys = protection["Keys"] as JsonArray;
        if (protection["Keys"] is not null && keys is null)
            throw new InvalidDataException("SecretProtection:Keys must be a JSON array.");
        keys ??= new JsonArray();
        var existing = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var node in keys)
        {
            var id = node?["KeyId"]?.GetValue<string>();
            var path = node?["Path"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(path) || !existing.TryAdd(id, path))
                throw new InvalidDataException("SecretProtection keys require unique KeyId values and file paths.");
            ValidateKey(id, Path.GetFullPath(path, AppContext.BaseDirectory));
        }

        if (!string.IsNullOrWhiteSpace(activeId) && !existing.ContainsKey(activeId))
            throw new InvalidDataException("ActiveKeyId does not identify a configured key. Restore the existing key configuration before continuing.");
        if (existing.Count > 0)
        {
            if (string.IsNullOrWhiteSpace(activeId))
                activeId = existing.Count == 1 ? existing.Keys.Single()
                    : throw new InvalidDataException("Multiple keys exist without an ActiveKeyId. Select the intended existing key before continuing.");
            var activePath = Path.GetFullPath(existing[activeId], AppContext.BaseDirectory);
            if (keyPath is not null && !string.Equals(activePath, keyPath,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidOperationException("A different active key is already configured. Set-secret-key preserves existing keys; it does not rotate them.");
            if (protection["ActiveKeyId"]?.GetValue<string>() != activeId)
            {
                protection["ActiveKeyId"] = activeId;
                await SaveAsync(settings, root, cancellationToken).ConfigureAwait(false);
            }
            Console.WriteLine($"Secret protection is configured in {selectedPath}. Existing keys retained.");
            Console.WriteLine("Restart the host if its secret-protection configuration has changed.");
            return 0;
        }

        activeId = "identity-" + Guid.NewGuid().ToString("N");
        keyPath ??= Path.Combine(Path.GetDirectoryName(selectedPath)!, "Keys", activeId + ".key");
        var created = false;
        try
        {
            if (File.Exists(keyPath)) ValidateKey(activeId, keyPath);
            else
            {
                IdentityCredentialCommands.CreateSecretProtectionKey(keyPath);
                created = true;
            }
            protection["ActiveKeyId"] = activeId;
            keys.Add(new JsonObject { ["KeyId"] = activeId, ["Path"] = keyPath });
            if (protection["Keys"] is null) protection["Keys"] = keys;
            await SaveAsync(settings, root, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (created) File.Delete(keyPath);
            throw;
        }
        Console.WriteLine($"Secret protection configured in {selectedPath}.");
        Console.WriteLine($"Key file: {keyPath}");
        Console.WriteLine("Restart the host to load the key. Persist and back up the settings and key file together.");
        return 0;
    }

    private static void ValidateKey(string id, string path)
    {
        try
        {
            var key = SecretProtectionKey.FromFile(id, path, isActive: false);
            try
            {
                if (key.Key.Length is not (16 or 24 or 32))
                    throw new ArgumentException("Invalid AES key length.");
            }
            finally { CryptographicOperations.ZeroMemory(key.Key); }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or FormatException or InvalidOperationException)
        {
            throw new InvalidDataException("An existing secret-protection key is missing, unreadable or invalid. Restore its original file; no key or settings were replaced.");
        }
    }

    private static Task SaveAsync(IdentitySettingsFile settings, JsonObject root, CancellationToken cancellationToken) =>
        settings.WriteAtomicAsync(JsonSerializer.SerializeToUtf8Bytes(root, new JsonSerializerOptions { WriteIndented = true }), cancellationToken);

    private static int Invalid(string toolName)
    {
        PrintUsage(toolName);
        return 2;
    }

    private static void PrintUsage(string toolName) =>
        Console.WriteLine($"Usage: {toolName} set-secret-key [--settings <appsettings.json>] [--key-file <persistent-key-file>]");
}
