using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Haley.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class ManagementSessionService(IOptionsMonitor<IdentityManagementOptions> options,
    AdminLoginLockoutService lockout, TimeProvider time)
{
    private readonly ConcurrentDictionary<string, (DateTimeOffset Expires, string Credential)> sessions = new();
    private readonly PasswordHasher<object> hasher = new();
    private static readonly object Credential = new();
    public bool Configured => options.CurrentValue.Enabled && !string.IsNullOrWhiteSpace(options.CurrentValue.PasswordHash);

    public async ValueTask<(string? Session, bool Locked)> LoginAsync(string? password, CancellationToken cancellationToken)
    {
        if (!Configured || string.IsNullOrEmpty(password) || password.Length > 1024) return (null, false);
        if ((await lockout.GetStatusAsync(cancellationToken)).IsLocked) return (null, true);
        var verified = PasswordVerificationResult.Failed;
        try { verified = hasher.VerifyHashedPassword(Credential, options.CurrentValue.PasswordHash, password); }
        catch (FormatException) { }
        if (verified == PasswordVerificationResult.Failed)
            return (null, (await lockout.RecordFailureAsync(cancellationToken)).IsLocked);
        await lockout.ResetAsync(cancellationToken);
        var now = time.GetUtcNow();
        foreach (var expired in sessions.Where(pair => pair.Value.Expires <= now).Select(pair => pair.Key)) sessions.TryRemove(expired, out _);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        sessions[token] = (now.AddMinutes(options.CurrentValue.SessionMinutes), Fingerprint());
        return (token, false);
    }

    public bool IsActive(string? session) => Configured && session is not null && sessions.TryGetValue(session, out var state) &&
        state.Expires > time.GetUtcNow() && state.Credential == Fingerprint();
    public void Revoke(string? session) { if (session is not null) sessions.TryRemove(session, out _); }
    private string Fingerprint() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(options.CurrentValue.PasswordHash)));
}
