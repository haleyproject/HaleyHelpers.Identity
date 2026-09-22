using Haley.Abstractions;
using Haley.Extensions;
using Haley.Models;
using Haley.Security;
using Haley.Services;
using Haley.Utils;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MySqlConnector;
using System.Security.Cryptography;
namespace Haley.Identity.Tests;

public sealed class IdentityDatabaseFixture : IAsyncDisposable
{
    public ServiceProvider Services { get; private set; } = null!;
    public TestClock Clock { get; } = new();
    public string Database { get; } = "hi_test_" + Guid.NewGuid().ToString("N");
    private readonly string _connection = Environment.GetEnvironmentVariable("HALEY_IDENTITY_TEST_CONNECTION")
        ?? throw new InvalidOperationException("An isolated MariaDB test connection is required.");
    public static async Task<IdentityDatabaseFixture> CreateAsync(IIdentityPersistenceExtension? extension = null)
    {
        var fixture = new IdentityDatabaseFixture();
        await fixture.InitializeAsync(extension);
        return fixture;
    }
    private async Task InitializeAsync(IIdentityPersistenceExtension? extension)
    {
        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:test"] = _connection + ";dbtype=maria;",
            ["AdapterStrings:identity"] = $"key=test;database={Database};",
            ["Haley:Identity:Server:Adapter"] = "identity",
            ["Haley:Identity:Server:Initialize"] = "false"
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var gateway = new ModularGateway(logger: null!, autoConfigure: false) { ThrowCRUDExceptions = true };
        gateway.SetConfigurationRoot(configuration); gateway.Configure(); gateway.SetDefaultAdapterKey("identity");
        var services = new ServiceCollection();
        services.AddLogging(); services.AddSingleton<IAdapterGateway>(gateway);
        services.AddSingleton<IIdentityClock>(Clock);
        services.AddSingleton<ISecretEnvelopeProtector>(new AesGcmSecretProtector([new SecretProtectionKey("test", RandomNumberGenerator.GetBytes(32), true)]));
        services.AddScoped<TestApplicationContext>();
        services.AddScoped<IIdentityApplicationContext>(provider => provider.GetRequiredService<TestApplicationContext>());
        if (extension is not null) services.AddSingleton(extension);
        services.AddHaleyIdentity(configuration, identity => identity.UseEmbedded(configuration));
        Services = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        await Services.GetRequiredService<IdentityDatabaseInstaller>().InstallAsync();
    }
    public IServiceScope Scope(Guid applicationId)
    {
        var scope = Services.CreateScope(); scope.ServiceProvider.GetRequiredService<TestApplicationContext>().ApplicationId = applicationId; return scope;
    }
    public async Task<object?> SqlAsync(string sql, params (string Name, object Value)[] parameters)
    {
        var builder = new MySqlConnectionStringBuilder(_connection) { Database = Database };
        await using var connection = new MySqlConnection(builder.ConnectionString); await connection.OpenAsync();
        await using var command = new MySqlCommand(sql, connection);
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        return await command.ExecuteScalarAsync();
    }
    public async ValueTask DisposeAsync()
    {
        if (Services is not null) await Services.DisposeAsync();
        if (!Database.StartsWith("hi_test_", StringComparison.Ordinal) || Database.Length != 40) throw new InvalidOperationException("Invalid disposable database name.");
        await using var connection = new MySqlConnection(_connection); await connection.OpenAsync();
        await using var command = new MySqlCommand($"DROP DATABASE IF EXISTS `{Database}`", connection); await command.ExecuteNonQueryAsync();
    }
}
