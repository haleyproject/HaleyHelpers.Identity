using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Haley.Utils;

/// <summary>Offline credential operations shared by host command-line tools.</summary>
public static class IdentityCredentialCommands
{
    private const int MinimumLength = 9;

    public static int HashAdminPassword(string[] args, string toolName)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine($"Usage: {toolName} hash-admin-password");
            return 2;
        }

        var password = ReadSecret("Superadmin password: ");
        if (password.Length < MinimumLength)
        {
            Console.Error.WriteLine(
                $"Password must contain at least {MinimumLength} characters.");
            return 2;
        }

        if (!Console.IsInputRedirected)
        {
            var confirmation = ReadSecret("Confirm password: ");
            if (!string.Equals(password, confirmation, StringComparison.Ordinal))
            {
                Console.Error.WriteLine("Passwords do not match.");
                return 2;
            }
        }

        var hasher = new PasswordHasher<object>(Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = 210_000
        }));
        Console.WriteLine(hasher.HashPassword(new object(), password));
        return 0;
    }

    private static string ReadSecret(string prompt)
    {
        if (Console.IsInputRedirected)
        {
            return Console.ReadLine() ?? string.Empty;
        }

        Console.Write(prompt);
        var buffer = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return buffer.ToString();
            }

            if (key.Key == ConsoleKey.Backspace && buffer.Length > 0)
            {
                buffer.Length--;
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Append(key.KeyChar);
            }
        }
    }

    public static int GenerateSecretProtectionKey(string[] args, string toolName, string configurationSection)
    {
        if (args.Length != 2 || string.IsNullOrWhiteSpace(args[1]))
        {
            Console.Error.WriteLine($"Usage: {toolName} generate-secret-protection-key <key-file>");
            return 2;
        }

        var path = Path.GetFullPath(args[1]);
        if (File.Exists(path))
        {
            Console.Error.WriteLine($"Refusing to replace the existing secret-protection key: {path}");
            return 3;
        }

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        Console.WriteLine($"Created a 32-byte secret-protection key at: {path}");
        Console.WriteLine($"Add it to {configurationSection}, persist it, and restart the identity host.");
        return 0;
    }
}
