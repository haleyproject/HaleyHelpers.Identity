using System.Text.Json;
using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.Configuration;

namespace Haley.Tools;

public static class ApplicationRegistrationCommands
{
    public static bool IsCommand(string[] args) => args.Length > 0 && args[0].ToLowerInvariant() is
        "register-application" or "list-applications" or "rotate-application-key" or "revoke-application-key" or "revoke-application" or "reactivate-application";

    public static async Task<int> RunAsync(string[] args)
    {
        var command = args[0].ToLowerInvariant();
        var values = new List<string>();
        string? settingsPath = null;
        Guid? requestedId = null;
        for (var index = 1; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--settings" when settingsPath is null && index + 1 < args.Length:
                    settingsPath = Path.GetFullPath(args[++index]);
                    break;
                case "--application-id" when command == "register-application" && requestedId is null && index + 1 < args.Length:
                    if (!Guid.TryParse(args[++index], out var id) || id == Guid.Empty) return Invalid();
                    requestedId = id;
                    break;
                default:
                    if (args[index].StartsWith("--", StringComparison.Ordinal)) return Invalid();
                    values.Add(args[index]);
                    break;
            }
        }
        settingsPath ??= Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        var environment = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
            ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";
        using var configuration = new ConfigurationManager();
        configuration.AddJsonFile(settingsPath, optional: true, reloadOnChange: false);
        if (Path.GetFileName(settingsPath).Equals("appsettings.json", StringComparison.OrdinalIgnoreCase))
            configuration.AddJsonFile(Path.Combine(Path.GetDirectoryName(settingsPath)!, $"appsettings.{environment}.json"),
                optional: true, reloadOnChange: false);
        if (environment.Equals("Development", StringComparison.OrdinalIgnoreCase))
            configuration.AddUserSecrets(typeof(ApplicationRegistrationCommands).Assembly, optional: true);
        configuration.AddEnvironmentVariables();
        var options = configuration.GetSection(IdentityServerOptions.SectionName).Get<IdentityServerOptions>() ?? new();
        var registry = new IdentityApplicationRegistry(options.SessionBindingKeys, settingsPath,
            initialApplications: options.Applications);
        if (command == "list-applications" && values.Count == 0)
        {
            Console.WriteLine(JsonSerializer.Serialize(registry.List(), new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        if (command == "register-application" && values.Count == 1)
            return Print(await registry.RegisterAsync(new(values[0], requestedId)).ConfigureAwait(false));
        if (values.Count == 0 || !Guid.TryParse(values[0], out var applicationId) || applicationId == Guid.Empty) return Invalid();
        return command switch
        {
            "rotate-application-key" when values.Count == 1 => Print(await registry.RotateAsync(applicationId).ConfigureAwait(false)),
            "revoke-application-key" when values.Count == 2 => Print(await registry.RevokeKeyAsync(applicationId, values[1]).ConfigureAwait(false)),
            "revoke-application" when values.Count == 1 => Print(await registry.RevokeAsync(applicationId).ConfigureAwait(false)),
            "reactivate-application" when values.Count == 1 => Print(await registry.ReactivateAsync(applicationId).ConfigureAwait(false)),
            _ => Invalid()
        };
    }

    private static int Print<T>(IFeedback<T> result)
    {
        if (!result.Status) { Console.Error.WriteLine(result.Message); return 1; }
        if (result.Result is IdentityApplicationCredential credential)
        {
            Console.Error.WriteLine(result.Message);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                Haley = new { Identity = credential }
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        else Console.WriteLine(result.Message);
        return 0;
    }

    private static int Invalid()
    {
        Console.Error.WriteLine("Invalid application command arguments. Run Haley.Identity.Cred --help.");
        return 2;
    }
}
