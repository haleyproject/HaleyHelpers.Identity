using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Haley.Security;
using Haley.Services;
using Haley.Utils;
using Xunit;

namespace Haley.Tests;

public sealed class SecretProtectionKeyCommandTests : IDisposable
{
    private const string Section = "Haley:Identity:Server:SecretProtection";
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("identity-protection-tests-");
    private string SettingsPath => Path.Combine(_root.FullName, "appsettings.json");
    private Task<int> RunAsync(params string[] arguments) => SecretProtectionKeyCommand.RunAsync(
        ["Set-Secret-Key", "--Settings", SettingsPath, .. arguments], "test", Section);

    [Fact]
    public async Task ConfiguresProtectionAndRepeatKeepsExistingCiphertextReadable()
    {
        await File.WriteAllTextAsync(SettingsPath, "{ /* retained values */ \"Unrelated\": {\"Port\":7430}, }",
            new System.Text.UTF8Encoding(true));
        Assert.Equal(0, await RunAsync());
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Assert.Equal(7430, root["Unrelated"]!["Port"]!.GetValue<int>());
        var protection = root["Haley"]!["Identity"]!["Server"]!["SecretProtection"]!;
        var id = protection["ActiveKeyId"]!.GetValue<string>();
        var keyPath = protection["Keys"]![0]!["Path"]!.GetValue<string>();
        Assert.Equal(id, protection["Keys"]![0]!["KeyId"]!.GetValue<string>());
        Assert.True(Path.IsPathFullyQualified(keyPath));
        Assert.Equal(32, new FileInfo(keyPath).Length);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyPath));
        var key = SecretProtectionKey.FromFile(id, keyPath);
        var before = await File.ReadAllTextAsync(SettingsPath);
        var envelope = new AesGcmSecretProtector([key], id).Protect("test-secret"u8, "totp-test");
        Assert.Equal(0, await RunAsync());
        Assert.Equal(before, await File.ReadAllTextAsync(SettingsPath));
        Assert.Single(Directory.GetFiles(Path.Combine(_root.FullName, "Keys")));
        var restored = SecretProtectionKey.FromFile(id, keyPath);
        Assert.Equal("test-secret"u8.ToArray(), new AesGcmSecretProtector([restored], id).Unprotect(envelope, "totp-test"));
        CryptographicOperations.ZeroMemory(key.Key);
        CryptographicOperations.ZeroMemory(restored.Key);
    }

    [Fact]
    public async Task ConcurrentSettersAndRegistryWritesPreserveBothSections()
    {
        await File.WriteAllTextAsync(SettingsPath, "{}");
        var registry = new IdentityApplicationRegistry(new(), SettingsPath);
        var registration = Task.Run(() => registry.RegisterAsync(new("Test backend")));
        var setup = Enumerable.Range(0, 6).Select(_ => Task.Run(() => RunAsync())).ToArray();
        Assert.All(await Task.WhenAll(setup), result => Assert.Equal(0, result));
        var credential = (await registration).Result;
        var reader = new IdentityApplicationRegistry(new(), SettingsPath);
        Assert.True(reader.Authenticate(credential.ApplicationId, credential.SessionKeyId, credential.SessionBindingSecret));
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Assert.Single(root["Haley"]!["Identity"]!["Server"]!["SecretProtection"]!["Keys"]!.AsArray());
        Assert.Single(Directory.GetFiles(Path.Combine(_root.FullName, "Keys")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrInvalidConfiguredKeyDoesNotReplaceFiles(bool invalid)
    {
        await File.WriteAllTextAsync(SettingsPath, "{}");
        Assert.Equal(0, await RunAsync());
        var before = await File.ReadAllTextAsync(SettingsPath);
        var path = JsonNode.Parse(before)!["Haley"]!["Identity"]!["Server"]!["SecretProtection"]!["Keys"]![0]!["Path"]!.GetValue<string>();
        if (invalid) await File.WriteAllTextAsync(path, "invalid-key");
        else File.Delete(path);
        await Assert.ThrowsAsync<InvalidDataException>(() => RunAsync());
        Assert.Equal(before, await File.ReadAllTextAsync(SettingsPath));
        if (invalid) Assert.Equal("invalid-key", await File.ReadAllTextAsync(path));
        else Assert.False(File.Exists(path));
    }

    [Theory]
    [InlineData("{partial")]
    [InlineData("{\"Haley\":{\"Identity\":{\"Server\":{\"SecretProtection\":{\"ActiveKeyId\":\"missing\",\"Keys\":[]}}}}}")]
    public async Task InvalidConfigurationDoesNotCreateKeys(string content)
    {
        await File.WriteAllTextAsync(SettingsPath, content);
        await Assert.ThrowsAsync<InvalidDataException>(() => RunAsync());
        Assert.Equal(content, await File.ReadAllTextAsync(SettingsPath));
        Assert.False(Directory.Exists(Path.Combine(_root.FullName, "Keys")));
    }

    [Fact]
    public async Task ExplicitExistingBase64KeyIsRegisteredWithoutChangingItsBytes()
    {
        await File.WriteAllTextAsync(SettingsPath, "{}");
        var path = Path.Combine(_root.FullName, "persistent.key");
        var content = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await File.WriteAllTextAsync(path, content);
        Assert.Equal(0, await RunAsync("--Key-File", path));
        Assert.Equal(content, await File.ReadAllTextAsync(path));
        var root = JsonNode.Parse(await File.ReadAllTextAsync(SettingsPath))!;
        Assert.Equal(path, root["Haley"]!["Identity"]!["Server"]!["SecretProtection"]!["Keys"]![0]!["Path"]!.GetValue<string>());
        var alternate = Path.Combine(_root.FullName, "alternate.key");
        await Assert.ThrowsAsync<InvalidOperationException>(() => RunAsync("--key-file", alternate));
        Assert.False(File.Exists(alternate));
    }

    [Fact]
    public async Task MissingSettingsAndIncompleteArgumentsDoNotCreateConfiguration()
    {
        await Assert.ThrowsAsync<FileNotFoundException>(() => RunAsync());
        Assert.Equal(2, await RunAsync("--key-file"));
        Assert.Empty(_root.EnumerateFileSystemInfos());
    }

    [SymbolicLinkTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SettingsSymlinkIsPreservedAndKeysUseLogicalHostDirectory(bool repeated)
    {
        var target = Path.Combine(_root.FullName, "Config", "appsettings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        await File.WriteAllTextAsync(target, "{}");
        File.CreateSymbolicLink(SettingsPath, target);
        Assert.Equal(0, await RunAsync());
        if (repeated) Assert.Equal(0, await RunAsync());
        Assert.NotNull(new FileInfo(SettingsPath).LinkTarget);
        var root = JsonNode.Parse(await File.ReadAllTextAsync(target))!;
        var keyPath = root["Haley"]!["Identity"]!["Server"]!["SecretProtection"]!["Keys"]![0]!["Path"]!.GetValue<string>();
        Assert.Equal(Path.Combine(_root.FullName, "Keys"), Path.GetDirectoryName(keyPath));
    }

    public void Dispose() => _root.Delete(recursive: true);
}
