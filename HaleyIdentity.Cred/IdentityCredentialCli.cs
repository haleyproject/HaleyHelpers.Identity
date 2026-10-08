using Haley.Utils;
using Microsoft.Extensions.Configuration;

namespace Haley.Tools;

public static class IdentityCredentialCli
{
    public static bool IsCredentialCommand(string[] args) =>
        ApplicationRegistrationCommands.IsCommand(args) || args.Length > 0 && args[0].ToLowerInvariant() is
            "hash-admin-password" or "hash-password" or
            "generate-secret-protection-key" or "set-secret-key" or "reset-lockout" or
            "help" or "--help" or "-h";

    public static int Run(string[] args)
    {
        const string tool = "Haley.Identity.Cred";
        const string section = "Haley:Identity:Management";
        try
        {
            if (args.Length == 0 || args[0].ToLowerInvariant() is "help" or "--help" or "-h" ||
                ApplicationRegistrationCommands.IsCommand(args) && args.Any(value => value is "--help" or "-h"))
            {
                Console.WriteLine("""
                    Haley.Identity.Cred: offline identity deployment credentials

                    Run directly with Haley.Identity.Cred <command>, or through the host:
                      dotnet Haley.Identity.Host.dll <command>
                    Credential commands exit before starting the web server or database setup.

                    hash-admin-password
                      Read a password without echoing, confirm it, and print its ASP.NET
                      Identity hash. Set Haley:Identity:Management:PasswordHash and restart.
                      Minimum 9 characters. Redirected input reads one line. No password arguments.

                    set-secret-key [--settings <appsettings.json>] [--key-file <persistent-key-file>]
                      Create a protection key and save ActiveKeyId and Keys automatically.
                      Defaults to appsettings.json beside this executable and its Keys directory.
                      Reuses a valid existing key; never replaces configured keys. Restart the host.
                      Persist the settings and key file together. No database access.

                    generate-secret-protection-key <key-file>
                      Create a new 32-byte key for Haley:Identity:Server:SecretProtection.
                      Existing files are never replaced. Persist this file outside the image.

                    reset-lockout <state-file>
                      Clear only the management login lockout. The host may remain online.
                      Use the configured Management:LoginLockoutStatePath. No database access.

                    register-application <display-name> [--application-id <guid>] [--settings <file>]
                      Register an application and print its generated backend credential once.
                    list-applications [--settings <file>]
                      List names, IDs, numeric lifecycle states and key IDs. Never lists secrets.
                    rotate-application-key <application-guid> [--settings <file>]
                      Issue a new key. Existing keys remain valid until explicitly revoked.
                    revoke-application-key <application-guid> <key-id> [--settings <file>]
                      Disable an old key after callers have switched to the new one.
                    revoke-application <application-guid> [--settings <file>]
                      Disable every key for the application. Does not delete user accounts.
                    reactivate-application <application-guid> [--settings <file>]
                      Reactivate a revoked application and print a fresh credential once.
                      The application ID is retained. Previously revoked keys remain invalid.

                    Application changes persist directly to appsettings.json beside this executable.
                    The running host checks for valid changes once per second, without restarting.
                    Use --settings to target another host appsettings.json, including its project file during F5.
                    Application secrets belong in calling backends, never browser configuration.

                    Browser cookie keys are created automatically by ASP.NET Data Protection.
                    Persist Management:KeyDirectory. They are separate from SecretProtection keys.
                    """);
                return 0;
            }
            if (ApplicationRegistrationCommands.IsCommand(args))
                return ApplicationRegistrationCommands.RunAsync(args).GetAwaiter().GetResult();
            return args[0].ToLowerInvariant() switch
            {
                "hash-admin-password" or "hash-password" => IdentityCredentialCommands.HashAdminPassword(args, tool),
                "generate-secret-protection-key" => IdentityCredentialCommands.GenerateSecretProtectionKey(args, tool, "Haley:Identity:Server:SecretProtection"),
                "set-secret-key" => SecretProtectionKeyCommand.RunAsync(args, tool, "Haley:Identity:Server:SecretProtection").GetAwaiter().GetResult(),
                "reset-lockout" when args.Length == 2 => AdminLoginLockoutFile.RunResetCommand([args[1]], section, tool),
                _ => Invalid()
            };
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static int Invalid()
    {
        Console.Error.WriteLine("Unknown or incomplete command. Run Haley.Identity.Cred --help.");
        return 2;
    }
}
