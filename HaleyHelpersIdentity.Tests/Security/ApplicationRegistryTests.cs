using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Hosting;
using Haley.Models;
using Haley.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Haley.Tests;

public sealed class ApplicationRegistryTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("identity-application-tests-");
    private string SettingsPath => Path.Combine(_root.FullName, "appsettings.json");
    private IdentityApplicationRegistry Open() => new(new(), SettingsPath);

    [Fact]
    public async Task RegistrationPersistsAndNeverListsSecrets()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
        await File.WriteAllTextAsync(SettingsPath, "{\"Unrelated\":{\"Port\":7430}}", new System.Text.UTF8Encoding(true));
        var registry = Open();
        var id = Guid.NewGuid();
        var result = await registry.RegisterAsync(new("LearnDesk", id));
        Assert.True(result.Status, result.Message);
        var credential = result.Result;
        Assert.Equal(id, credential.ApplicationId);
        Assert.True(registry.Authenticate(id, credential.SessionKeyId, credential.SessionBindingSecret));
        Assert.False(registry.Authenticate(Guid.NewGuid(), credential.SessionKeyId, credential.SessionBindingSecret));
        var serialized = JsonSerializer.Serialize(registry.List());
        Assert.DoesNotContain(credential.SessionBindingSecret, serialized);
        Assert.DoesNotContain("SessionBindingSecret", serialized);
        Assert.Equal("LearnDesk", registry.List().Single().DisplayName);
        Assert.True(Open().Authenticate(id, credential.SessionKeyId, credential.SessionBindingSecret));
        var settings = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Assert.Equal(7430, settings["Unrelated"]!["Port"]!.GetValue<int>());
        Assert.Equal(409, (await registry.RegisterAsync(new("LearnDesk"))).Code);
    }

    [Fact]
    public async Task RotationAndRevocationReachAnotherRunningRegistryAndSurviveRestart()
    {
        var reader = Open();
        var writer = Open();
        var original = (await writer.RegisterAsync(new("Application"))).Result;
        Assert.Equal('7', original.ApplicationId.ToString("D")[14]);
        await reader.ReloadAsync();
        Assert.True(Accepts(reader, original));
        var replacement = (await writer.RotateAsync(original.ApplicationId)).Result;
        await reader.ReloadAsync();
        Assert.True(Accepts(reader, original));
        Assert.True(Accepts(reader, replacement));
        Assert.True((await writer.RevokeKeyAsync(original.ApplicationId, original.SessionKeyId)).Status);
        await reader.ReloadAsync();
        Assert.False(Accepts(reader, original));
        Assert.True(Accepts(reader, replacement));
        Assert.Equal(409, (await writer.RevokeKeyAsync(original.ApplicationId, replacement.SessionKeyId)).Code);
        Assert.True((await writer.RevokeAsync(original.ApplicationId)).Status);
        await reader.ReloadAsync();
        Assert.False(Accepts(reader, replacement));
        Assert.False(Accepts(Open(), replacement));
        Assert.Equal(IdentityRecordStatus.Revoked, reader.List().Single().Status);
        Assert.Empty(reader.List().Single().KeyIds);
        Assert.Equal(409, (await writer.RotateAsync(original.ApplicationId)).Code);
    }

    [Fact]
    public async Task InvalidOrMissingConfigurationRetainsLastValidRegistryAndCannotBeOverwrittenByAnEdit()
    {
        var reader = Open();
        var writer = Open();
        var credential = (await writer.RegisterAsync(new("Application"))).Result;
        await reader.ReloadAsync();
        var valid = await File.ReadAllTextAsync(SettingsPath);
        await File.WriteAllTextAsync(SettingsPath, "{partial");
        await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReloadAsync());
        Assert.True(Accepts(reader, credential));
        await Assert.ThrowsAsync<InvalidDataException>(() => writer.RotateAsync(credential.ApplicationId));
        Assert.Equal("{partial", await File.ReadAllTextAsync(SettingsPath));
        var malformed = JsonNode.Parse(valid)!;
        malformed["Haley"]!["Identity"]!["Server"]!["Applications"]![credential.ApplicationId.ToString("D")]!["Status"] = "Active";
        await File.WriteAllTextAsync(SettingsPath, malformed.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReloadAsync());
        Assert.True(Accepts(reader, credential));
        File.Delete(SettingsPath);
        await Assert.ThrowsAsync<IOException>(() => reader.ReloadAsync());
        Assert.True(Accepts(reader, credential));
        await File.WriteAllTextAsync(SettingsPath, valid);
        await writer.RevokeAsync(credential.ApplicationId);
        await reader.ReloadAsync();
        Assert.False(Accepts(reader, credential));
    }

    [Fact]
    public async Task ConcurrentWritersPreserveAllApplicationsAndSerializeDuplicateRegistrations()
    {
        var writers = Enumerable.Range(0, 10).Select(_ => Open()).ToArray();
        var results = await Task.WhenAll(writers.Select((writer, index) => writer.RegisterAsync(new("App " + index))));
        Assert.All(results, result => Assert.True(result.Status, result.Message));
        Assert.Equal(10, Open().List().Count);
        var duplicate = await Task.WhenAll(writers.Select(writer => writer.RegisterAsync(new("Same name"))));
        Assert.Single(duplicate, result => result.Status);
        Assert.Equal(11, Open().List().Count);
    }

    [Fact]
    public async Task RevocationOverridesStaticConfigurationAndRemovingManagedEntriesDoesNotResurrectThem()
    {
        var id = Guid.NewGuid();
        var seed = new Dictionary<string, Dictionary<string, string>> { [id.ToString("D")] = new() { ["legacy"] = "legacy-application-secret-with-32-characters" } };
        var registry = new IdentityApplicationRegistry(seed, SettingsPath);
        Assert.True(registry.Authenticate(id, "legacy", seed[id.ToString("D")]["legacy"]));
        await registry.RevokeAsync(id);
        Assert.False(new IdentityApplicationRegistry(seed, SettingsPath).Authenticate(id, "legacy", seed[id.ToString("D")]["legacy"]));
        await File.WriteAllTextAsync(SettingsPath, "{}");
        await registry.ReloadAsync();
        Assert.False(registry.Authenticate(id, "legacy", seed[id.ToString("D")]["legacy"]));
    }

    private static bool Accepts(IdentityApplicationRegistry registry, IdentityApplicationCredential credential) =>
        registry.Authenticate(credential.ApplicationId, credential.SessionKeyId, credential.SessionBindingSecret);

    [Fact]
    public async Task RotationPreservesExistingConfiguredKeyLabels()
    {
        var id = Guid.NewGuid();
        const string label = "Quarter 4 (legacy)";
        const string secret = "legacy-application-secret-with-32-characters";
        var registry = new IdentityApplicationRegistry(new() { [id.ToString("D")] = new() { [label] = secret } }, SettingsPath);
        var rotated = await registry.RotateAsync(id);
        Assert.True(rotated.Status, rotated.Message);
        Assert.True(registry.Authenticate(id, label, secret));
        Assert.True(Open().Authenticate(id, label, secret));
        Assert.Contains(label, Open().List().Single().KeyIds);
    }

    [Fact]
    public async Task MetadataAndExternalCredentialsJoinByIdAndManagedRevocationSurvivesRestart()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        await WriteMetadataAsync(first, second);
        var external = ExternalKeys(first, second);
        var registry = FromConfiguration(external);
        Assert.Equal(new[] { "LearnDesk", "Paperless" }, registry.List().Select(app => app.DisplayName));
        Assert.True(registry.Authenticate(first, "external", external[$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{first:D}:external"]!));
        var renamed = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        renamed["Haley"]!["Identity"]!["Server"]!["Applications"]![second.ToString("D")]!["DisplayName"] = "Paperless updated";
        await File.WriteAllTextAsync(SettingsPath, renamed.ToJsonString());
        await registry.ReloadAsync();
        Assert.Equal("Paperless updated", registry.List().Single(app => app.ApplicationId == second).DisplayName);
        Assert.True(registry.Authenticate(second, "external", external[$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{second:D}:external"]!));
        var rotated = await registry.RotateAsync(first);
        Assert.True(rotated.Status, rotated.Message);
        Assert.True(Accepts(FromConfiguration(external), rotated.Result));
        Assert.True((await registry.RevokeKeyAsync(first, "external")).Status);
        Assert.False(FromConfiguration(external).Authenticate(first, "external", external[$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{first:D}:external"]!));
        Assert.True((await registry.RevokeAsync(first)).Status);
        var restarted = FromConfiguration(external);
        Assert.False(Accepts(restarted, rotated.Result));
        Assert.Equal(IdentityRecordStatus.Revoked, restarted.List().Single(app => app.ApplicationId == first).Status);
        var persisted = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Assert.Null(persisted["Haley"]!["Identity"]!["Server"]!["SessionBindingKeys"]![second.ToString("D")]);
    }

    [Fact]
    public async Task HigherPriorityConfigurationProvidesMetadataForExternallyConfiguredKeys()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        await WriteMetadataAsync(first, second);
        var external = ExternalKeys(first, second);
        external[$"{IdentityServerOptions.SectionName}:Applications:{first:D}:DisplayName"] = "Configured name";
        external[$"{IdentityServerOptions.SectionName}:Applications:{first:D}:Status"] = "64";
        var registry = FromConfiguration(external);
        var configured = registry.List().Single(app => app.ApplicationId == first);
        Assert.Equal("Configured name", configured.DisplayName);
        Assert.Equal(IdentityRecordStatus.Revoked, configured.Status);
        Assert.Empty(configured.KeyIds);
    }

    [Fact]
    public async Task HostUsesItsNormalAppsettingsAndDoesNotLoadAnExtraConfigDirectory()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        await WriteMetadataAsync(first, second);
        var ignoredFile = Path.Combine(_root.FullName, "Config", "appsettings.json");
        var oldRegistry = new IdentityApplicationRegistry(new(), ignoredFile);
        Assert.True((await oldRegistry.RegisterAsync(new("Old registration"))).Status);
        var originalIgnoredFile = await File.ReadAllBytesAsync(ignoredFile);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = _root.FullName,
            EnvironmentName = "Production"
        });
        var settings = ExternalKeys(first, second);
        settings["ConnectionStrings:identity"] = "server=127.0.0.1;port=1;user=test;password=test-only;dbtype=maria;";
        settings["AdapterStrings:identity"] = "key=identity;database=identity_configuration_test;";
        settings[$"{IdentityServerOptions.SectionName}:Adapter"] = "identity";
        settings[$"{IdentityServerOptions.SectionName}:Initialize"] = "false";
        settings[$"{IdentityServerOptions.SectionName}:TrustedNetwork"] = "true";
        builder.Configuration.AddInMemoryCollection(settings);
        IdentityHosting.ConfigureBuilder(builder);
        await using var app = builder.Build();
        var registry = app.Services.GetRequiredService<IdentityApplicationRegistry>();
        Assert.Equal(new[] { "LearnDesk", "Paperless" }, registry.List().Select(entry => entry.DisplayName));
        Assert.True((await registry.RegisterAsync(new("New registration"))).Status);
        Assert.Contains("New registration", await File.ReadAllTextAsync(SettingsPath));
        Assert.Equal(originalIgnoredFile, await File.ReadAllBytesAsync(ignoredFile));
        Assert.All(builder.Configuration.Sources.OfType<Microsoft.Extensions.Configuration.Json.JsonConfigurationSource>()
            .Where(source => Path.GetFileName(source.Path) == "appsettings.json"), source => Assert.False(source.ReloadOnChange));
        await File.WriteAllTextAsync(SettingsPath, "{incomplete");
        await Assert.ThrowsAsync<InvalidDataException>(() => registry.ReloadAsync());
        Assert.Equal(3, registry.List().Count);
    }

    [Fact]
    public async Task ExternalMetadataSurvivesMutatingAnExistingFileKeyRing()
    {
        var credential = (await Open().RegisterAsync(new("Original name"))).Result;
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        root["Haley"]!["Identity"]!["Server"]!.AsObject().Remove("Applications");
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        var registry = FromConfiguration(new()
        {
            [$"{IdentityServerOptions.SectionName}:Applications:{credential.ApplicationId:D}:DisplayName"] = "External name",
            [$"{IdentityServerOptions.SectionName}:Applications:{credential.ApplicationId:D}:Status"] = "2"
        });
        Assert.Equal("External name", registry.List().Single().DisplayName);
        Assert.True((await registry.RotateAsync(credential.ApplicationId)).Status);
        Assert.Equal("External name", Open().List().Single().DisplayName);
    }

    [SymbolicLinkTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PersistenceFollowsSymlinksAndSharesTheTargetLock(bool targetExists)
    {
        var target = Path.Combine(_root.FullName, "volume", "appsettings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        if (targetExists) await File.WriteAllTextAsync(target, "{}");
        File.CreateSymbolicLink(SettingsPath, target);
        var throughLink = Open();
        var throughTarget = new IdentityApplicationRegistry(new(), target);
        var registered = await Task.WhenAll(throughLink.RegisterAsync(new("Linked app")), throughTarget.RegisterAsync(new("Direct app")));
        Assert.All(registered, result => Assert.True(result.Status, result.Message));
        Assert.NotNull(new FileInfo(SettingsPath).LinkTarget);
        Assert.Equal(2, Open().List().Count);
        Assert.Equal(await File.ReadAllTextAsync(target), await File.ReadAllTextAsync(SettingsPath));
    }

    private Task WriteMetadataAsync(Guid first, Guid second) => File.WriteAllTextAsync(SettingsPath,
        JsonSerializer.Serialize(new { Haley = new { Identity = new { Server = new { Applications = new Dictionary<string, IdentityApplicationOptions>
        {
            [first.ToString("D")] = new() { DisplayName = "LearnDesk", Status = IdentityRecordStatus.Active },
            [second.ToString("D")] = new() { DisplayName = "Paperless", Status = IdentityRecordStatus.Active }
        } } } } }));

    private static Dictionary<string, string?> ExternalKeys(Guid first, Guid second) => new()
    {
        [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{first:D}:external"] = "first-test-application-secret-with-32-characters",
        [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{second:D}:external"] = "second-test-application-secret-with-32-characters"
    };

    private IdentityApplicationRegistry FromConfiguration(Dictionary<string, string?> external)
    {
        using var configuration = new ConfigurationManager();
        configuration.AddJsonFile(SettingsPath).AddInMemoryCollection(external);
        var options = configuration.GetSection(IdentityServerOptions.SectionName).Get<IdentityServerOptions>()!;
        return new(options.SessionBindingKeys, SettingsPath, initialApplications: options.Applications);
    }

    public void Dispose() => _root.Delete(recursive: true);
}
