using Haley.DAL;
using System.Security.Cryptography;
using System.Text;
using Haley.Internal;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class IdentityDatabaseInstaller : DALUtilBase
{
    private readonly IAdapterGateway _gateway;
    private readonly IOptions<IdentityServerOptions> _options;
    public IdentityDatabaseInstaller(IAdapterGateway gateway, IOptions<IdentityServerOptions> options)
        : base(gateway, options.Value.Adapter)
    {
        _gateway = gateway;
        _options = options;
    }

    public async ValueTask InstallAsync(CancellationToken cancellationToken = default)
    {
        var assembly = typeof(IdentityDatabaseInstaller).Assembly;
        var schema = Encoding.UTF8.GetString(ResourceUtils.GetEmbeddedResource(IdentityDatabase.SchemaResource, assembly)
            ?? throw new InvalidOperationException("The canonical Identity schema resource is missing."));
        var seed = Encoding.UTF8.GetString(ResourceUtils.GetEmbeddedResource(IdentityDatabase.SeedResource, assembly)
            ?? throw new InvalidOperationException("The canonical Identity seed resource is missing."));
        var result = await _gateway.BootstrapDatabaseAsync(new DatabaseBootstrapArgs(_options.Value.Adapter)
        {
            SqlContent = IdentityDatabaseQueries.Install(schema, seed, Hash(schema), Hash(seed))
        }, cancellationToken).ConfigureAwait(false);
        if (result is null || !result.Status)
            throw new InvalidOperationException($"Identity database initialization failed: {result?.Message ?? "no result returned"}.");
        if (await ScalarAsync<long>(IdentityDatabaseQueries.CheckSessionShape, new(cancellationToken)).ConfigureAwait(false) != 2)
            throw new InvalidOperationException("This Identity database requires the manual Haley extraction migration before this server can start.");
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
