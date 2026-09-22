using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class IdentityDatabaseHostedService(IdentityDatabaseInstaller installer,
    IOptions<IdentityServerOptions> options) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.Value.Initialize) await installer.InstallAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
