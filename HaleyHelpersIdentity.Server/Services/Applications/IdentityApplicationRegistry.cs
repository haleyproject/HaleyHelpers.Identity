using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Security;
using Haley.Utils;
using Microsoft.Extensions.Configuration;

namespace Haley.Services;

/// <summary>Application authentication and configuration persistence shared by the host and credential CLI.</summary>
public sealed class IdentityApplicationRegistry
{
    private const string KeysProperty = "SessionBindingKeys";
    private const string MetadataProperty = "Applications";
    private readonly IdentitySettingsFile? _settings;
    private readonly IIdentityUuidGenerator _ids;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Snapshot _seed;
    private readonly HashSet<Guid> _managedIds = [];
    private readonly HashSet<string> _fileIssuePaths = new(StringComparer.OrdinalIgnoreCase);
    private Snapshot _snapshot;
    private byte[]? _lastContent;
    private bool _fileSeen;

    public IdentityApplicationRegistry(Dictionary<string, Dictionary<string, string>> initialKeys, string? settingsPath = null,
        IIdentityUuidGenerator? ids = null, Dictionary<string, IdentityApplicationOptions>? initialApplications = null)
        : this(JsonSerializer.SerializeToNode(new { SessionBindingKeys = initialKeys, Applications = initialApplications })!.AsObject(), settingsPath, ids)
    {
    }

    private IdentityApplicationRegistry(JsonObject configured, string? settingsPath, IIdentityUuidGenerator? ids)
    {
        _ids = ids ?? new Uuid7Generator(new SystemClock());
        _settings = settingsPath is null ? null : new IdentitySettingsFile(settingsPath);
        // A persisted revocation must also disable credentials supplied by another configuration provider.
        foreach (var pair in ObjectProperty(configured, MetadataProperty))
            if (pair.Value is JsonObject info && info["Status"] is JsonValue status &&
                status.TryGetValue<int>(out var value) && value == (int)IdentityRecordStatus.Revoked)
                ObjectProperty(configured, KeysProperty)[pair.Key] = new JsonObject();
        _seed = ReadEntries(configured);
        if (_settings is not null && File.Exists(_settings.FilePath))
        {
            _lastContent = ReadContent();
            var server = Server(IdentitySettingsFile.Parse(_lastContent), false);
            var stored = ReadEntries(server, _seed, useConfiguredMetadata: true);
            RememberFileIssues(stored);
            TakeOwnership(server);
            _snapshot = Merge(stored);
            _fileSeen = true;
        }
        else _snapshot = _seed;
    }

    /// <summary>Reads application entries without allowing a malformed entry to break host options binding.</summary>
    public static IdentityApplicationRegistry FromConfiguration(IConfiguration configuration, string? settingsPath = null,
        IIdentityUuidGenerator? ids = null)
    {
        var section = configuration.GetSection(IdentityServerOptions.SectionName);
        var server = new JsonObject();
        foreach (var property in new[] { KeysProperty, MetadataProperty })
        {
            var applications = new JsonObject();
            foreach (var application in section.GetSection(property).GetChildren())
            {
                if (application.Value is not null) { applications[application.Key] = application.Value; continue; }
                var values = new JsonObject();
                foreach (var value in application.GetChildren())
                {
                    if (property == MetadataProperty && value.Key.Equals("Status", StringComparison.OrdinalIgnoreCase) &&
                        int.TryParse(value.Value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var status))
                        values["Status"] = status;
                    else
                    {
                        var name = property == MetadataProperty && value.Key.Equals("DisplayName", StringComparison.OrdinalIgnoreCase) ? "DisplayName"
                            : property == MetadataProperty && value.Key.Equals("Status", StringComparison.OrdinalIgnoreCase) ? "Status" : value.Key;
                        values[name] = value.Value is null && value.GetChildren().Any() ? new JsonObject() : JsonValue.Create(value.Value);
                    }
                }
                applications[application.Key] = values;
            }
            server[property] = applications;
        }
        return new(server, settingsPath, ids);
    }

    internal void ConfigureOptions(IdentityServerOptions options)
    {
        foreach (var pair in _snapshot.Entries)
        {
            options.SessionBindingKeys[pair.Key.ToString("D")] = pair.Value.Issue is null
                ? new(pair.Value.Keys, StringComparer.Ordinal) : new(StringComparer.Ordinal);
            options.Applications[pair.Key.ToString("D")] = new() { DisplayName = pair.Value.Name, Status = pair.Value.Status };
        }
    }

    public IReadOnlyList<RegisteredIdentityApplication> List() => Volatile.Read(ref _snapshot).Entries
        .Select(pair => new RegisteredIdentityApplication(pair.Key, ValidName(pair.Value.Name) ? pair.Value.Name : pair.Key.ToString("D"),
            pair.Value.Issue is null ? pair.Value.Status : IdentityRecordStatus.Inactive,
            pair.Value.Issue is null ? pair.Value.Keys.Keys.Order(StringComparer.Ordinal).ToArray() : Array.Empty<string>())
            { ConfigurationError = pair.Value.Issue?.Message })
        .OrderBy(app => app.DisplayName, StringComparer.OrdinalIgnoreCase).ThenBy(app => app.ApplicationId).ToArray();

    public IReadOnlyList<IdentityApplicationConfigurationIssue> ConfigurationIssues() => Volatile.Read(ref _snapshot).Issues;

    public bool Authenticate(Guid applicationId, string keyId, string secret)
    {
        if (string.IsNullOrEmpty(keyId) || secret.Length is < 32 or > 512 ||
            !Volatile.Read(ref _snapshot).Entries.TryGetValue(applicationId, out var app) ||
            app.Issue is not null || app.Status != IdentityRecordStatus.Active || !app.Keys.TryGetValue(keyId, out var expected)) return false;
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
            RememberFileIssues(stored);
            TakeOwnership(server);
            var next = Merge(stored);
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
        if (app.Issue is not null) return InvalidConfiguration<IdentityApplicationCredential>(app);
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
        if (app.Issue is not null) return InvalidConfiguration<bool>(app);
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
        if (app.Issue is not null) return InvalidConfiguration<IdentityApplicationCredential>(app);
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
        if (app.Issue is not null) return InvalidConfiguration<bool>(app);
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
            var result = change(root, Merge(ReadEntries(Server(root, false), _seed)).Entries);
            if (!result.Status) return result;
            var stored = ReadEntries(Server(root, false), _seed);
            RememberFileIssues(stored);
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

    private Snapshot Merge(Snapshot stored)
    {
        var entries = _seed.Entries.Where(pair => !_managedIds.Contains(pair.Key)).ToDictionary(pair => pair.Key, pair => pair.Value);
        foreach (var pair in stored.Entries) entries[pair.Key] = pair.Value;
        DisableDuplicateNames(entries);
        return SnapshotFor(entries, stored.Issues.Where(issue => issue.ApplicationId is null)
            .Concat(_seed.Issues.Where(issue => issue.ApplicationId is null && !_fileIssuePaths.Contains(issue.ConfigurationPath))));
    }

    private void RememberFileIssues(Snapshot stored)
    {
        foreach (var issue in stored.Issues.Where(issue => issue.ApplicationId is null)) _fileIssuePaths.Add(issue.ConfigurationPath);
    }

    private void TakeOwnership(JsonObject server)
    {
        // Metadata alone may rely on credentials in User Secrets or environment variables.
        // A saved key ring, including an empty revoked ring, owns the complete credential set.
        foreach (var pair in ObjectProperty(server, KeysProperty))
            if (Guid.TryParseExact(pair.Key, "D", out var id) && id != Guid.Empty) _managedIds.Add(id);
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
        // Preserve application ID aliases so validation can disable an ambiguous entry
        // without JsonObject's case-insensitive dictionary rejecting the whole registry.
        foreach (var property in new[] { KeysProperty, MetadataProperty })
            if (root[property] is JsonObject applications)
                root[property] = JsonNode.Parse(applications.ToJsonString(), new JsonNodeOptions { PropertyNameCaseInsensitive = false });
        return root;
    }

    private Snapshot ReadEntries(JsonObject server, Snapshot? configured = null,
        bool useConfiguredMetadata = false)
    {
        var keyRings = ObjectProperty(server, KeysProperty);
        var metadata = ObjectProperty(server, MetadataProperty);
        var entries = new Dictionary<Guid, Entry>();
        var unidentified = new List<IdentityApplicationConfigurationIssue>();
        foreach (var text in keyRings.Select(pair => pair.Key).Concat(metadata.Select(pair => pair.Key)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Guid.TryParseExact(text, "D", out var id) || id == Guid.Empty)
            {
                var property = keyRings.ContainsKey(text) ? KeysProperty : MetadataProperty;
                unidentified.Add(new(null, $"{IdentityServerOptions.SectionName}:{property}",
                    $"An application entry under '{IdentityServerOptions.SectionName}:{property}' was ignored because its identifier is not a nonempty GUID in D format."));
                continue;
            }
            if (entries.ContainsKey(id)) continue;
            Entry? fallback = null;
            configured?.Entries.TryGetValue(id, out fallback);
            var keyEntries = keyRings.Where(pair => Guid.TryParseExact(pair.Key, "D", out var keyId) && keyId == id).ToArray();
            var metadataEntries = metadata.Where(pair => Guid.TryParseExact(pair.Key, "D", out var metadataId) && metadataId == id).ToArray();
            var ownsKeys = keyEntries.Length > 0;
            var keys = !ownsKeys && !_managedIds.Contains(id) && fallback is not null
                ? new Dictionary<string, string>(fallback.Keys, StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal);
            var name = fallback?.Name ?? id.ToString("D");
            var status = fallback?.Status ?? IdentityRecordStatus.Revoked;
            var keysValidated = false;
            var path = $"{IdentityServerOptions.SectionName}:{MetadataProperty}:{id:D}";
            try
            {
                if (keyEntries.Length > 1 || metadataEntries.Length > 1)
                    throw new InvalidDataException($"Application '{id:D}' has duplicate configuration entries. Use the application ID only once in each application section.");
                path = $"{IdentityServerOptions.SectionName}:{KeysProperty}:{id:D}";
                var ring = keyEntries.FirstOrDefault().Value;
                if (ring is not null && ring is not JsonObject)
                    throw new InvalidDataException($"Application '{id:D}' requires a JSON key object at '{path}'.");
                foreach (var key in ring as JsonObject ?? new JsonObject())
                {
                    if (string.IsNullOrWhiteSpace(key.Key) || key.Value is not JsonValue value ||
                        !value.TryGetValue<string>(out var secret) || secret.Length is < 32 or > 512)
                        throw new InvalidDataException($"Application '{id:D}' has an invalid key at '{path}'. Each key needs an identifier and a secret of 32 to 512 characters.");
                    keys.Add(key.Key, secret);
                }
                keysValidated = true;
                status = fallback?.Status ?? (keys.Count > 0 ? IdentityRecordStatus.Active : IdentityRecordStatus.Revoked);
                path = $"{IdentityServerOptions.SectionName}:{MetadataProperty}:{id:D}";
                var infoNode = metadataEntries.FirstOrDefault().Value;
                if (infoNode is not null && infoNode is not JsonObject)
                    throw new InvalidDataException($"Application '{id:D}' requires a JSON metadata object at '{path}'.");
                var info = infoNode as JsonObject ?? new JsonObject();
                if (info.GroupBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() > 1))
                    throw new InvalidDataException($"Application '{id:D}' has duplicate metadata fields at '{path}'.");
                var displayName = info.FirstOrDefault(pair => pair.Key.Equals("DisplayName", StringComparison.OrdinalIgnoreCase)).Value;
                var lifecycle = info.FirstOrDefault(pair => pair.Key.Equals("Status", StringComparison.OrdinalIgnoreCase)).Value;
                if (displayName is not null && (displayName is not JsonValue nameValue || !nameValue.TryGetValue(out name)))
                    throw new InvalidDataException($"Application '{id:D}' requires a string at '{path}:DisplayName'.");
                if (lifecycle is not null)
                {
                    if (lifecycle is not JsonValue statusValue || !statusValue.TryGetValue<int>(out var numericStatus))
                        throw new InvalidDataException($"Application '{id:D}' requires an integer status flag at '{path}:Status'.");
                    status = (IdentityRecordStatus)numericStatus;
                }
                if (useConfiguredMetadata && !ownsKeys && fallback is not null)
                {
                    name = fallback.Name;
                    status = fallback.Status;
                    if (fallback.Issue is not null) throw new InvalidDataException(fallback.Issue.Message);
                }
                if (!ownsKeys && status == IdentityRecordStatus.Revoked) keys.Clear();
                if (!ValidName(name))
                    throw new InvalidDataException($"Application '{id:D}' requires a display name of 1 to 120 characters without control characters at '{path}:DisplayName'.");
                if (status is not (IdentityRecordStatus.Active or IdentityRecordStatus.Revoked))
                    throw new InvalidDataException($"Application '{id:D}' requires status 2 (Active) or 64 (Revoked) at '{path}:Status'.");
                path = $"{IdentityServerOptions.SectionName}:{KeysProperty}:{id:D}";
                if (status == IdentityRecordStatus.Active && keys.Count == 0)
                    throw new InvalidDataException($"Active application '{id:D}' has no session binding keys. Configure at least one key at '{path}' in the effective host configuration, including development User Secrets when applicable.");
                if (status == IdentityRecordStatus.Revoked && keys.Count != 0)
                    throw new InvalidDataException($"Revoked application '{id:D}' must have no keys at '{path}'.");
                entries.Add(id, new(name!, status, keys));
            }
            catch (InvalidDataException error)
            {
                // Only an entirely valid key ring may be retained privately for metadata repair.
                // Invalid or partially parsed rings must never become a fallback on a later reload.
                entries.Add(id, new(name ?? id.ToString("D"), status,
                    keysValidated ? keys : new(StringComparer.Ordinal), new(id, path, error.Message)));
            }
        }
        DisableDuplicateNames(entries);
        return SnapshotFor(entries, unidentified);
    }

    private static bool ValidName(string? name) => !string.IsNullOrWhiteSpace(name) && name.Length <= 120 && !name.Any(char.IsControl);

    private static void DisableDuplicateNames(Dictionary<Guid, Entry> entries)
    {
        foreach (var group in entries.Where(pair => ValidName(pair.Value.Name)).GroupBy(pair => pair.Value.Name, StringComparer.OrdinalIgnoreCase).Where(group => group.Count() > 1))
            foreach (var pair in group)
            {
                var path = $"{IdentityServerOptions.SectionName}:{MetadataProperty}:{pair.Key:D}:DisplayName";
                entries[pair.Key] = pair.Value with { Issue = pair.Value.Issue ??
                    new(pair.Key, path, $"Application '{pair.Key:D}' has a duplicate display name at '{path}'. Application display names must be unique.") };
            }
    }

    private static Snapshot SnapshotFor(Dictionary<Guid, Entry> entries, IEnumerable<IdentityApplicationConfigurationIssue> unidentified) =>
        new(entries, entries.Values.Where(entry => entry.Issue is not null).Select(entry => entry.Issue!).Concat(unidentified).Distinct().ToArray());

    private static JsonObject ObjectProperty(JsonObject parent, string name) => parent[name] is null ? new JsonObject()
        : parent[name] as JsonObject ?? throw new InvalidDataException("Application registry sections must be JSON objects.");

    private static void WriteEntry(JsonObject root, Guid applicationId, Entry entry)
    {
        var server = Server(root, true);
        server[KeysProperty] ??= new JsonObject();
        server[MetadataProperty] ??= new JsonObject();
        var id = applicationId.ToString("D");
        foreach (var property in new[] { KeysProperty, MetadataProperty })
            foreach (var alias in server[property]!.AsObject().Select(pair => pair.Key)
                .Where(key => Guid.TryParseExact(key, "D", out var parsed) && parsed == applicationId).ToArray())
                server[property]!.AsObject().Remove(alias);
        server[KeysProperty]![id] = JsonSerializer.SerializeToNode(entry.Keys);
        server[MetadataProperty]![id] = new JsonObject { ["DisplayName"] = entry.Name, ["Status"] = (int)entry.Status };
    }

    private static IdentityApplicationCredential NewCredential(Guid id) => new(id, "key-" + Guid.NewGuid().ToString("N"),
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
    private static IFeedback<T> Success<T>(T result, string message) => new Feedback<T>(true, message, result) { Code = 200 };
    private static IFeedback<T> Failure<T>(int code, string key, string message) => new Feedback<T>(false, message) { Code = code, Key = key };
    private static IFeedback<T> Missing<T>() => Failure<T>(404, "application_not_found", "The application was not found.");

    private static IFeedback<T> InvalidConfiguration<T>(Entry entry) => Failure<T>(409, "invalid_application_configuration", entry.Issue!.Message);

    private sealed record Entry(string Name, IdentityRecordStatus Status, Dictionary<string, string> Keys,
        IdentityApplicationConfigurationIssue? Issue = null);

    private sealed record Snapshot(Dictionary<Guid, Entry> Entries, IReadOnlyList<IdentityApplicationConfigurationIssue> Issues);
}
