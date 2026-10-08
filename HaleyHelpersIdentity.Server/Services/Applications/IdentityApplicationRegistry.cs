using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Security;
using Haley.Utils;

namespace Haley.Services;

/// <summary>Application authentication and configuration persistence shared by the host and credential CLI.</summary>
public sealed class IdentityApplicationRegistry
{
    private const string KeysProperty = "SessionBindingKeys";
    private const string MetadataProperty = "Applications";
    private readonly IdentitySettingsFile? _settings;
    private readonly IIdentityUuidGenerator _ids;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<Guid, Entry> _seed;
    private readonly HashSet<Guid> _managedIds = [];
    private Dictionary<Guid, Entry> _snapshot;
    private byte[]? _lastContent;
    private bool _fileSeen;

    public IdentityApplicationRegistry(Dictionary<string, Dictionary<string, string>> initialKeys, string? settingsPath = null,
        IIdentityUuidGenerator? ids = null, Dictionary<string, IdentityApplicationOptions>? initialApplications = null)
    {
        _ids = ids ?? new Uuid7Generator(new SystemClock());
        _settings = settingsPath is null ? null : new IdentitySettingsFile(settingsPath);
        var configured = JsonSerializer.SerializeToNode(new { SessionBindingKeys = initialKeys, Applications = initialApplications })!.AsObject();
        // A persisted revocation must also disable credentials supplied by another configuration provider.
        foreach (var pair in initialApplications ?? [])
            if (pair.Value.Status == IdentityRecordStatus.Revoked) configured[KeysProperty]![pair.Key] = new JsonObject();
        _seed = ReadEntries(configured);
        if (_settings is not null && File.Exists(_settings.FilePath))
        {
            _lastContent = ReadContent();
            var server = Server(IdentitySettingsFile.Parse(_lastContent), false);
            var stored = ReadEntries(server, _seed, useConfiguredMetadata: true);
            _snapshot = Merge(stored);
            TakeOwnership(server);
            _fileSeen = true;
        }
        else _snapshot = new(_seed);
    }

    public IReadOnlyList<RegisteredIdentityApplication> List() => Volatile.Read(ref _snapshot)
        .Select(pair => new RegisteredIdentityApplication(pair.Key, pair.Value.Name, pair.Value.Status,
            pair.Value.Keys.Keys.Order(StringComparer.Ordinal).ToArray()))
        .OrderBy(app => app.DisplayName, StringComparer.OrdinalIgnoreCase).ThenBy(app => app.ApplicationId).ToArray();

    public bool Authenticate(Guid applicationId, string keyId, string secret)
    {
        if (string.IsNullOrEmpty(keyId) || secret.Length is < 32 or > 512 ||
            !Volatile.Read(ref _snapshot).TryGetValue(applicationId, out var app) ||
            app.Status != IdentityRecordStatus.Active || !app.Keys.TryGetValue(keyId, out var expected)) return false;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(secret)),
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
    }

    public async Task ReloadAsync(CancellationToken cancellationToken = default)
    {
        if (_settings is null) return;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var content = ReadContent();
            if (_lastContent is not null && content.AsSpan().SequenceEqual(_lastContent)) return;
            var server = Server(IdentitySettingsFile.Parse(content), false);
            var stored = ReadEntries(server, _seed);
            var next = Merge(stored);
            TakeOwnership(server);
            Volatile.Write(ref _snapshot, next);
            _lastContent = content;
            _fileSeen |= File.Exists(_settings.FilePath);
        }
        finally { _gate.Release(); }
    }

    public Task<IFeedback<IdentityApplicationCredential>> RegisterAsync(RegisterIdentityApplicationRequest request,
        CancellationToken cancellationToken = default) => MutateAsync((root, entries) =>
    {
        var name = request.DisplayName?.Trim();
        if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || name.Any(char.IsControl) || request.ApplicationId == Guid.Empty)
            return Failure<IdentityApplicationCredential>(400, "invalid_application", "Supply a display name of 1 to 120 characters and a valid application ID, or omit the ID to generate one.");
        var id = request.ApplicationId ?? _ids.NewUuid7();
        if (entries.ContainsKey(id) || entries.Values.Any(app => app.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            return Failure<IdentityApplicationCredential>(409, "application_exists", "An application with that ID or display name already exists.");
        var credential = NewCredential(id);
        WriteEntry(root, id, new(name, IdentityRecordStatus.Active, new(StringComparer.Ordinal) { [credential.SessionKeyId] = credential.SessionBindingSecret }));
        return Success(credential, "Application registered. Save the new credential now.");
    }, cancellationToken);

    public Task<IFeedback<IdentityApplicationCredential>> RotateAsync(Guid applicationId,
        CancellationToken cancellationToken = default) => MutateAsync((root, entries) =>
    {
        if (!entries.TryGetValue(applicationId, out var app)) return Missing<IdentityApplicationCredential>();
        if (app.Status != IdentityRecordStatus.Active)
            return Failure<IdentityApplicationCredential>(409, "application_revoked", "A revoked application cannot receive a new key.");
        var credential = NewCredential(applicationId);
        var keys = new Dictionary<string, string>(app.Keys, StringComparer.Ordinal) { [credential.SessionKeyId] = credential.SessionBindingSecret };
        WriteEntry(root, applicationId, app with { Keys = keys });
        return Success(credential, "New key issued. Existing keys remain valid until explicitly revoked.");
    }, cancellationToken);

    public Task<IFeedback<bool>> RevokeKeyAsync(Guid applicationId, string keyId,
        CancellationToken cancellationToken = default) => MutateAsync((root, entries) =>
    {
        if (!entries.TryGetValue(applicationId, out var app)) return Missing<bool>();
        if (!app.Keys.ContainsKey(keyId)) return Failure<bool>(404, "application_key_not_found", "The application key was not found.");
        if (app.Keys.Count == 1)
            return Failure<bool>(409, "last_application_key", "Revoke the application to remove its final key, or rotate it first.");
        var keys = new Dictionary<string, string>(app.Keys, StringComparer.Ordinal);
        keys.Remove(keyId);
        WriteEntry(root, applicationId, app with { Keys = keys });
        return Success(true, "Application key revoked.");
    }, cancellationToken);

    public Task<IFeedback<IdentityApplicationCredential>> ReactivateAsync(Guid applicationId,
        CancellationToken cancellationToken = default) => MutateAsync((root, entries) =>
    {
        if (!entries.TryGetValue(applicationId, out var app)) return Missing<IdentityApplicationCredential>();
        if (app.Status != IdentityRecordStatus.Revoked)
            return Failure<IdentityApplicationCredential>(409, "application_active", "The application is already active. Rotate its key to issue another credential.");
        var credential = NewCredential(applicationId);
        WriteEntry(root, applicationId, app with
        {
            Status = IdentityRecordStatus.Active,
            Keys = new(StringComparer.Ordinal) { [credential.SessionKeyId] = credential.SessionBindingSecret }
        });
        return Success(credential, "Application reactivated. Save the new credential now; previously revoked keys remain invalid.");
    }, cancellationToken);

    public Task<IFeedback<bool>> RevokeAsync(Guid applicationId,
        CancellationToken cancellationToken = default) => MutateAsync((root, entries) =>
    {
        if (!entries.TryGetValue(applicationId, out var app)) return Missing<bool>();
        WriteEntry(root, applicationId, app with { Status = IdentityRecordStatus.Revoked, Keys = new(StringComparer.Ordinal) });
        return Success(true, "Application revoked. All of its keys are disabled.");
    }, cancellationToken);

    private async Task<IFeedback<T>> MutateAsync<T>(Func<JsonObject, Dictionary<Guid, Entry>, IFeedback<T>> change,
        CancellationToken cancellationToken)
    {
        if (_settings is null) throw new InvalidOperationException("Application registration requires a writable settings file.");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var fileLock = await _settings.AcquireLockAsync(cancellationToken).ConfigureAwait(false);
            var root = IdentitySettingsFile.Parse(ReadContent());
            var result = change(root, Merge(ReadEntries(Server(root, false), _seed)));
            if (!result.Status) return result;
            var stored = ReadEntries(Server(root, false), _seed);
            var next = Merge(stored);
            var content = JsonSerializer.SerializeToUtf8Bytes(root, new JsonSerializerOptions { WriteIndented = true });
            await _settings.WriteAtomicAsync(content, cancellationToken).ConfigureAwait(false);
            TakeOwnership(Server(root, false));
            Volatile.Write(ref _snapshot, next);
            _lastContent = content;
            _fileSeen = true;
            return result;
        }
        finally { _gate.Release(); }
    }

    private byte[] ReadContent() => _settings?.ReadContent(_fileSeen) ?? "{}"u8.ToArray();

    private Dictionary<Guid, Entry> Merge(Dictionary<Guid, Entry> stored)
    {
        var entries = _seed.Where(pair => !_managedIds.Contains(pair.Key)).ToDictionary(pair => pair.Key, pair => pair.Value);
        foreach (var pair in stored) entries[pair.Key] = pair.Value;
        if (entries.Values.Select(entry => entry.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Count)
            throw new InvalidDataException("Application display names must be unique.");
        return entries;
    }

    private void TakeOwnership(JsonObject server)
    {
        // Metadata alone may rely on credentials in User Secrets or environment variables.
        // A saved key ring, including an empty revoked ring, owns the complete credential set.
        foreach (var pair in ObjectProperty(server, KeysProperty)) _managedIds.Add(Guid.Parse(pair.Key));
    }

    private static JsonObject Server(JsonObject root, bool create)
    {
        foreach (var name in new[] { "Haley", "Identity", "Server" })
        {
            if (root[name] is null)
            {
                if (!create) return new JsonObject();
                root[name] = new JsonObject();
            }
            root = root[name] as JsonObject ?? throw new InvalidDataException("The identity settings hierarchy must contain JSON objects.");
        }
        return root;
    }

    private Dictionary<Guid, Entry> ReadEntries(JsonObject server, IReadOnlyDictionary<Guid, Entry>? configured = null,
        bool useConfiguredMetadata = false)
    {
        var keyRings = ObjectProperty(server, KeysProperty);
        var metadata = ObjectProperty(server, MetadataProperty);
        var entries = new Dictionary<Guid, Entry>();
        foreach (var text in keyRings.Select(pair => pair.Key).Concat(metadata.Select(pair => pair.Key)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Guid.TryParseExact(text, "D", out var id) || id == Guid.Empty || entries.ContainsKey(id))
                throw new InvalidDataException("Application registry entries require unique, nonempty GUIDs.");
            Entry? fallback = null;
            configured?.TryGetValue(id, out fallback);
            var ownsKeys = keyRings[text] is not null;
            var keys = !ownsKeys && !_managedIds.Contains(id) && fallback is not null
                ? new Dictionary<string, string>(fallback.Keys, StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var key in ObjectProperty(keyRings, text))
            {
                if (string.IsNullOrWhiteSpace(key.Key) || key.Value is not JsonValue value ||
                    !value.TryGetValue<string>(out var secret) || secret.Length is < 32 or > 512)
                    throw new InvalidDataException("Application keys require a key ID and a secret of 32 to 512 characters.");
                keys.Add(key.Key, secret);
            }
            var info = ObjectProperty(metadata, text);
            var name = fallback?.Name ?? id.ToString("D");
            var status = fallback?.Status ?? (keys.Count > 0 ? IdentityRecordStatus.Active : IdentityRecordStatus.Revoked);
            if (info["DisplayName"] is not null && (info["DisplayName"] is not JsonValue nameValue || !nameValue.TryGetValue(out name)))
                throw new InvalidDataException("Application display names must be strings.");
            if (info["Status"] is not null)
            {
                if (info["Status"] is not JsonValue statusValue || !statusValue.TryGetValue<int>(out var numericStatus))
                    throw new InvalidDataException("Application status must be a supported integer flag.");
                status = (IdentityRecordStatus)numericStatus;
            }
            if (useConfiguredMetadata && !ownsKeys && fallback is not null)
            {
                name = fallback.Name;
                status = fallback.Status;
            }
            if (!ownsKeys && status == IdentityRecordStatus.Revoked) keys.Clear();
            if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || name.Any(char.IsControl) ||
                status is not (IdentityRecordStatus.Active or IdentityRecordStatus.Revoked) ||
                (status == IdentityRecordStatus.Active && keys.Count == 0) || (status == IdentityRecordStatus.Revoked && keys.Count != 0))
                throw new InvalidDataException("Application metadata or lifecycle state is invalid.");
            entries.Add(id, new(name, status, keys));
        }
        if (entries.Values.Select(entry => entry.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Count)
            throw new InvalidDataException("Application display names must be unique.");
        return entries;
    }

    private static JsonObject ObjectProperty(JsonObject parent, string name) => parent[name] is null ? new JsonObject()
        : parent[name] as JsonObject ?? throw new InvalidDataException("Application registry sections must be JSON objects.");

    private static void WriteEntry(JsonObject root, Guid applicationId, Entry entry)
    {
        var server = Server(root, true);
        server[KeysProperty] ??= new JsonObject();
        server[MetadataProperty] ??= new JsonObject();
        var id = applicationId.ToString("D");
        server[KeysProperty]![id] = JsonSerializer.SerializeToNode(entry.Keys);
        server[MetadataProperty]![id] = new JsonObject { ["DisplayName"] = entry.Name, ["Status"] = (int)entry.Status };
    }

    private static IdentityApplicationCredential NewCredential(Guid id) => new(id, "key-" + Guid.NewGuid().ToString("N"),
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
    private static IFeedback<T> Success<T>(T result, string message) => new Feedback<T>(true, message, result) { Code = 200 };
    private static IFeedback<T> Failure<T>(int code, string key, string message) => new Feedback<T>(false, message) { Code = code, Key = key };
    private static IFeedback<T> Missing<T>() => Failure<T>(404, "application_not_found", "The application was not found.");

    private sealed record Entry(string Name, IdentityRecordStatus Status, Dictionary<string, string> Keys);
}
