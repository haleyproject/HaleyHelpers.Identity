using Haley.Utils;
using Microsoft.Extensions.Configuration;

namespace Haley.Tools;

public static class IdentityCredentialCli
{
    public static bool IsCredentialCommand(string[] args) =>
        args.Length > 0 && args[0].ToLowerInvariant() is
            "hash-admin-password" or "hash-password" or
            "generate-secret-protection-key" or "reset-lockout" or
            "help" or "--help" or "-h";

    public static int Run(string[] args)
    {
        const string tool = "Haley.Identity.Cred";
        const string section = "Haley:Identity:Management";
        try
        {
            if (args.Length == 0 || args[0].ToLowerInvariant() is "help" or "--help" or "-h")
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

                    generate-secret-protection-key <key-file>
                      Create a new 32-byte key for Haley:Identity:Server:SecretProtection.
                      Existing files are never replaced. Persist this file outside the image.

                    reset-lockout <state-file>
                      Clear only the management login lockout. The host may remain online.
                      Use the configured Management:LoginLockoutStatePath. No database access.

                    Browser cookie keys are created automatically by ASP.NET Data Protection.
                    Persist Management:KeyDirectory. They are separate from SecretProtection keys.
                    """);
                return 0;
            }
            return args[0].ToLowerInvariant() switch
            {
                "hash-admin-password" or "hash-password" => IdentityCredentialCommands.HashAdminPassword(args, tool),
                "generate-secret-protection-key" => IdentityCredentialCommands.GenerateSecretProtectionKey(args, tool, "Haley:Identity:Server:SecretProtection"),
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
