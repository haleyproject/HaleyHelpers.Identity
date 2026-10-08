using Haley.Services;

namespace Haley.Hosting;

public sealed class ApplicationRegistryReloadService(IdentityApplicationRegistry registry,
    ILogger<ApplicationRegistryReloadService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var failed = false;
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await registry.ReloadAsync(stoppingToken).ConfigureAwait(false);
                if (failed) logger.LogInformation("Application registry reload recovered.");
                failed = false;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
            {
                // Do not log settings contents or exception data that could contain a credential.
                if (!failed) logger.LogError("Application registry reload failed ({ErrorType}); retaining the last valid registry.", error.GetType().Name);
                failed = true;
            }
        }
    }
}
