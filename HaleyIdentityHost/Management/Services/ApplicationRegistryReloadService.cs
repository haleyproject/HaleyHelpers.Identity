using Haley.Services;
using Haley.Models;

namespace Haley.Hosting;

public sealed class ApplicationRegistryReloadService(IdentityApplicationRegistry registry,
    ILogger<ApplicationRegistryReloadService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var failed = false;
        var issues = LogConfigurationIssues([]);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await registry.ReloadAsync(stoppingToken).ConfigureAwait(false);
                issues = LogConfigurationIssues(issues);
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

    private HashSet<IdentityApplicationConfigurationIssue> LogConfigurationIssues(HashSet<IdentityApplicationConfigurationIssue> previous)
    {
        var current = registry.ConfigurationIssues().ToHashSet();
        foreach (var issue in current.Except(previous))
            logger.LogError("Application configuration is invalid at {ConfigurationPath} (application {ApplicationId}): {ConfigurationError}",
                issue.ConfigurationPath, issue.ApplicationId, issue.Message);
        foreach (var issue in previous.Except(current))
            logger.LogInformation("Application configuration error cleared at {ConfigurationPath} (application {ApplicationId}).",
                issue.ConfigurationPath, issue.ApplicationId);
        return current;
    }
}
