using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Abstractions;
using Haley.Hosting;
using Haley.Extensions;
using Haley.Models;
using Haley.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Tests;

public sealed class ApplicationConfigurationIsolationTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("identity-app-isolation-");
    private string SettingsPath => Path.Combine(_root.FullName, "appsettings.json");

    public static IEnumerable<object[]> InvalidEntries()
    {
        foreach (var kind in new[] { "missing-keys", "short-key", "partial-key-ring", "key-object", "metadata-object", "status-text", "status-flags", "display-name", "duplicate-id" })
            foreach (var startup in new[] { true, false }) yield return [kind, startup];
    }

    [Theory]
    [MemberData(nameof(InvalidEntries))]
    public async Task InvalidEntriesOnlyDisableTheirApplicationAndRecoverWithoutChangingCredentials(string kind, bool startup)
    {
        var (running, first, second) = await CreateAsync();
        var original = await File.ReadAllTextAsync(SettingsPath);
        await CorruptAsync(kind, second);
        var malformed = await File.ReadAllBytesAsync(SettingsPath);
        var registry = startup ? Open() : running;
        if (!startup) await registry.ReloadAsync();

        Assert.True(Accepts(registry, first));
        Assert.False(Accepts(registry, second));
        var disabled = registry.List().Single(app => app.ApplicationId == second.ApplicationId);
        Assert.Equal(IdentityRecordStatus.Inactive, disabled.Status);
        Assert.Empty(disabled.KeyIds);
        Assert.NotEmpty(disabled.ConfigurationError!);
        var issue = Assert.Single(registry.ConfigurationIssues());
        Assert.Equal(second.ApplicationId, issue.ApplicationId);
        var diagnostics = JsonSerializer.Serialize(new { Applications = registry.List(), Issues = registry.ConfigurationIssues() });
        Assert.DoesNotContain(first.SessionBindingSecret, diagnostics);
        Assert.DoesNotContain(second.SessionBindingSecret, diagnostics);
        Assert.Equal(malformed, await File.ReadAllBytesAsync(SettingsPath));

        await File.WriteAllTextAsync(SettingsPath, original);
        await registry.ReloadAsync();
        Assert.True(Accepts(registry, first));
        Assert.True(Accepts(registry, second));
        Assert.Empty(registry.ConfigurationIssues());
        Assert.True(Accepts(Open(), second));
    }

    [Fact]
    public async Task CorrectedFileMetadataReusesUnchangedExternalKeysAfterAnInvalidStartup()
    {
        var (_, first, second) = await CreateAsync();
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Server(root).Remove("SessionBindingKeys");
        Server(root)["Applications"]![second.ApplicationId.ToString("D")]!["Status"] = "not-a-status";
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        using var configuration = new ConfigurationManager();
        configuration.AddJsonFile(SettingsPath).AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{first.ApplicationId:D}:{first.SessionKeyId}"] = first.SessionBindingSecret,
            [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{second.ApplicationId:D}:{second.SessionKeyId}"] = second.SessionBindingSecret
        });
        var registry = IdentityApplicationRegistry.FromConfiguration(configuration, SettingsPath);
        Assert.True(Accepts(registry, first));
        Assert.False(Accepts(registry, second));
        Assert.Empty(registry.List().Single(app => app.ApplicationId == second.ApplicationId).KeyIds);
        Server(root)["Applications"]![second.ApplicationId.ToString("D")]!["Status"] = 2;
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        await registry.ReloadAsync();
        Assert.True(Accepts(registry, first));
        Assert.True(Accepts(registry, second));
        Assert.Empty(registry.ConfigurationIssues());
        Assert.Null(Server(JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!)["SessionBindingKeys"]);
    }

    [Fact]
    public async Task InvalidExternalKeyRingsNeverBecomeUsableAfterAnUnrelatedFileEdit()
    {
        var (_, first, second) = await CreateAsync();
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Server(root).Remove("SessionBindingKeys");
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        using var configuration = new ConfigurationManager();
        configuration.AddJsonFile(SettingsPath).AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{first.ApplicationId:D}:{first.SessionKeyId}"] = first.SessionBindingSecret,
            [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{second.ApplicationId:D}:{second.SessionKeyId}"] = second.SessionBindingSecret,
            [$"{IdentityServerOptions.SectionName}:SessionBindingKeys:{second.ApplicationId:D}:zz-invalid"] = "too-short"
        });
        var registry = IdentityApplicationRegistry.FromConfiguration(configuration, SettingsPath);
        Assert.True(Accepts(registry, first));
        Assert.False(Accepts(registry, second));
        Server(root)["Applications"]![second.ApplicationId.ToString("D")]!["DisplayName"] = "Updated second application";
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        await registry.ReloadAsync();
        Assert.True(Accepts(registry, first));
        Assert.False(Accepts(registry, second));
        Assert.Equal(second.ApplicationId, Assert.Single(registry.ConfigurationIssues()).ApplicationId);
    }

    [Fact]
    public async Task HealthyApplicationsRemainManageableWhileInvalidEntriesArePreserved()
    {
        var (registry, first, second) = await CreateAsync();
        await CorruptAsync("short-key", second);
        var before = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        await registry.ReloadAsync();
        var rejected = await registry.RotateAsync(second.ApplicationId);
        Assert.False(rejected.Status);
        Assert.Equal(409, rejected.Code);
        Assert.Equal("invalid_application_configuration", rejected.Key);
        var rotated = await registry.RotateAsync(first.ApplicationId);
        Assert.True(rotated.Status, rotated.Message);
        Assert.True(Accepts(registry, first));
        Assert.True(Accepts(registry, rotated.Result));
        Assert.False(Accepts(registry, second));
        var registered = await registry.RegisterAsync(new("Another healthy application"));
        Assert.True(registered.Status, registered.Message);
        var after = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        foreach (var section in new[] { "Applications", "SessionBindingKeys" })
            Assert.True(JsonNode.DeepEquals(Server(before)[section]![second.ApplicationId.ToString("D")],
                Server(after)[section]![second.ApplicationId.ToString("D")]));
        Assert.Equal(second.ApplicationId, Assert.Single(registry.ConfigurationIssues()).ApplicationId);
    }

    [Fact]
    public async Task DuplicateDisplayNamesDisableConflictingEntriesAndPreserveUnrelatedApplications()
    {
        var (registry, first, second) = await CreateAsync();
        var third = await registry.RegisterAsync(new("Third application"));
        Assert.True(third.Status, third.Message);
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Server(root)["Applications"]![second.ApplicationId.ToString("D")]!["DisplayName"] = "First application";
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        var restarted = Open();
        Assert.False(Accepts(restarted, first));
        Assert.False(Accepts(restarted, second));
        Assert.True(Accepts(restarted, third.Result));
        Assert.Equal(2, restarted.ConfigurationIssues().Count);
    }

    [Fact]
    public async Task InvalidApplicationIdentifiersAreReportedWithoutDisablingValidApplications()
    {
        var (registry, first, second) = await CreateAsync();
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Server(root)["Applications"]!["not-an-application-id"] = new JsonObject { ["DisplayName"] = "Invalid entry", ["Status"] = 2 };
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        var restarted = Open();
        Assert.True(Accepts(restarted, first));
        Assert.True(Accepts(restarted, second));
        Assert.Null(Assert.Single(restarted.ConfigurationIssues()).ApplicationId);
        Server(root)["Applications"]!.AsObject().Remove("not-an-application-id");
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        await restarted.ReloadAsync();
        Assert.Empty(restarted.ConfigurationIssues());
    }

    [Theory]
    [InlineData("missing-keys")]
    [InlineData("short-key")]
    [InlineData("status-text")]
    [InlineData("partial-key-ring")]
    public async Task RealHostStartsAndServesHealthyApplicationsWithInvalidNeighbors(string kind)
    {
        var (_, first, second) = await CreateAsync();
        await CorruptAsync(kind, second);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = _root.FullName,
            EnvironmentName = "Production"
        });
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{IdentityServerOptions.SectionName}:Adapter"] = "identity",
            [$"{IdentityServerOptions.SectionName}:Initialize"] = "false",
            [$"{IdentityServerOptions.SectionName}:TrustedNetwork"] = "true",
            ["AdapterStrings:identity"] = "key=identity;database=application_configuration_test;",
            ["ConnectionStrings:identity"] = "server=127.0.0.1;port=1;user=test;password=test-only;dbtype=maria;",
            ["Haley:Identity:Management:Enabled"] = "false",
            ["Haley:Identity:Management:KeyDirectory"] = Path.Combine(_root.FullName, "AdminKeys"),
            ["Haley:Identity:Management:LoginLockoutStatePath"] = Path.Combine(_root.FullName, "lockout.json")
        });
        builder.Services.AddSingleton(DispatchProxy.Create<IIdentity, RateLimitedIdentityProxy>());
        IdentityHosting.ConfigureBuilder(builder);
        await using var app = builder.Build();
        IdentityHosting.ConfigureApplication(app);
        await app.StartAsync();
        var options = app.Services.GetRequiredService<IOptions<IdentityServerOptions>>().Value;
        Assert.Empty(options.SessionBindingKeys[second.ApplicationId.ToString("D")]);
        var fallback = new IdentityApplicationRegistry(options.SessionBindingKeys, initialApplications: options.Applications);
        Assert.False(Accepts(fallback, second));
        var registry = app.Services.GetRequiredService<IdentityApplicationRegistry>();
        Assert.True(Accepts(registry, first));
        Assert.False(Accepts(registry, second));
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Haley-Application-Id", first.ApplicationId.ToString("D"));
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key-Id", first.SessionKeyId);
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key", first.SessionBindingSecret);
        using var allowed = await client.GetAsync($"/api/identity/accounts/{Guid.NewGuid():D}");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        client.DefaultRequestHeaders.Remove("X-Haley-Application-Id");
        client.DefaultRequestHeaders.Remove("X-Haley-Session-Key-Id");
        client.DefaultRequestHeaders.Remove("X-Haley-Session-Key");
        client.DefaultRequestHeaders.Add("X-Haley-Application-Id", second.ApplicationId.ToString("D"));
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key-Id", second.SessionKeyId);
        client.DefaultRequestHeaders.Add("X-Haley-Session-Key", second.SessionBindingSecret);
        using var denied = await client.GetAsync($"/api/identity/accounts/{Guid.NewGuid():D}");
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        using var diagnostics = await client.GetAsync("/admin/api/applications/configuration-issues");
        Assert.NotEqual(HttpStatusCode.OK, diagnostics.StatusCode);
        Assert.DoesNotContain("ConfigurationPath", await diagnostics.Content.ReadAsStringAsync());
        await app.StopAsync();
    }

    [Fact]
    public async Task ApplicationIdentifierAndMetadataCasingRemainUsableDuringRotation()
    {
        var (_, first, second) = await CreateAsync();
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        var id = second.ApplicationId.ToString("D");
        foreach (var section in new[] { "Applications", "SessionBindingKeys" })
        {
            var entries = Server(root)[section]!.AsObject();
            var entry = entries[id]!.DeepClone();
            entries.Remove(id);
            entries[id.ToUpperInvariant()] = entry;
        }
        Server(root)["Applications"]![id.ToUpperInvariant()] = new JsonObject { ["displayname"] = "Second application", ["status"] = 2 };
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
        var registry = Open();
        Assert.True(Accepts(registry, first));
        Assert.True(Accepts(registry, second));
        var rotated = await registry.RotateAsync(second.ApplicationId);
        Assert.True(rotated.Status, rotated.Message);
        Assert.True(Accepts(Open(), second));
        Assert.True(Accepts(Open(), rotated.Result));
        Assert.Empty(registry.ConfigurationIssues());
    }

    [Fact]
    public void HostWideOptionsStillRejectInvalidSessionConfiguration()
    {
        using var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{IdentityServerOptions.SectionName}:Adapter"] = "identity",
            [$"{IdentityServerOptions.SectionName}:SessionSeconds"] = "1"
        });
        var services = new ServiceCollection();
        services.AddHaleyIdentityEngine(configuration, registerInitializer: false);
        using var provider = services.BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<IdentityServerOptions>>().Value);
    }

    private async Task<(IdentityApplicationRegistry Registry, IdentityApplicationCredential First, IdentityApplicationCredential Second)> CreateAsync()
    {
        var registry = Open();
        var first = await registry.RegisterAsync(new("First application"));
        var second = await registry.RegisterAsync(new("Second application", Guid.Parse("00000000-0000-7000-8000-0000000000ab")));
        Assert.True(first.Status, first.Message);
        Assert.True(second.Status, second.Message);
        return (registry, first.Result, second.Result);
    }

    private async Task CorruptAsync(string kind, IdentityApplicationCredential credential)
    {
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        var server = Server(root);
        var id = credential.ApplicationId.ToString("D");
        switch (kind)
        {
            case "missing-keys": server["SessionBindingKeys"]![id] = new JsonObject(); break;
            case "short-key": server["SessionBindingKeys"]![id]![credential.SessionKeyId] = "too-short"; break;
            case "partial-key-ring": server["SessionBindingKeys"]![id]!["bad"] = "too-short"; break;
            case "key-object": server["SessionBindingKeys"]![id] = 7; break;
            case "metadata-object": server["Applications"]![id] = "invalid"; break;
            case "status-text": server["Applications"]![id]!["Status"] = "not-a-status"; break;
            case "status-flags": server["Applications"]![id]!["Status"] = 3; break;
            case "display-name": server["Applications"]![id]!["DisplayName"] = ""; break;
            case "duplicate-id": server["SessionBindingKeys"]![id.ToUpperInvariant()] = server["SessionBindingKeys"]![id]!.DeepClone(); break;
            default: throw new ArgumentOutOfRangeException(nameof(kind));
        }
        await File.WriteAllTextAsync(SettingsPath, root.ToJsonString());
    }

    private IdentityApplicationRegistry Open() => new(new(), SettingsPath);
    private static JsonObject Server(JsonNode root) => root["Haley"]!["Identity"]!["Server"]!.AsObject();
    private static bool Accepts(IdentityApplicationRegistry registry, IdentityApplicationCredential credential) =>
        registry.Authenticate(credential.ApplicationId, credential.SessionKeyId, credential.SessionBindingSecret);
    public void Dispose() => _root.Delete(recursive: true);
}
