using Haley.Abstractions;
using Haley.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class MfaPersistenceTests
{
    [MariaDbFact]
    public async Task PasswordFreeAccountsCanEnrollAndVerifyMfaWithReplayAndRecoveryProtection()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(); using var scope = database.Scope(Guid.NewGuid());
        var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var account = await client.EnsureAccountAsync(new("mfa@example.test")); Assert.True(account.Status, account.Message);
        var enrollment = await client.BeginTotpEnrollmentAsync(new(account.Result.UserId, "MFA Test")); Assert.True(enrollment.Status, enrollment.Message);
        var details = await client.InspectTotpEnrollmentAsync(enrollment.Result.Ticket); Assert.True(details.Status, details.Message);
        var secret = QueryHelpers.ParseQuery(new Uri(details.Result.OtpauthUri).Query)["secret"].ToString();
        var confirmation = await client.ConfirmTotpEnrollmentAsync(new(enrollment.Result.Ticket, Code(secret, database.Clock.UtcNow)));
        Assert.True(confirmation.Status, confirmation.Message);
        Assert.False((await client.ConfirmTotpEnrollmentAsync(new(enrollment.Result.Ticket, Code(secret, database.Clock.UtcNow)))).Status);
        database.Clock.UtcNow = database.Clock.UtcNow.AddSeconds(30);
        var request = new VerifyMfaRequest(account.Result.UserId, enrollment.Result.MethodId, MfaKind.Totp, Code(secret, database.Clock.UtcNow));
        Assert.True((await client.VerifyMfaAsync(request)).Status); Assert.False((await client.VerifyMfaAsync(request)).Status);
        var recovery = await client.ReplaceRecoveryCodesAsync(new(account.Result.UserId, 5)); Assert.True(recovery.Status, recovery.Message);
        var recoveryRequest = new VerifyMfaRequest(account.Result.UserId, null, MfaKind.RecoveryCode, recovery.Result.Codes.First());
        Assert.True((await client.VerifyMfaAsync(recoveryRequest)).Status); Assert.False((await client.VerifyMfaAsync(recoveryRequest)).Status);
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM credential")));
    }
    internal static string Code(string base32, DateTimeOffset at)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = string.Concat(base32.TrimEnd('=').Select(c => Convert.ToString(alphabet.IndexOf(c), 2).PadLeft(5, '0')));
        var key = Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
        Span<byte> counter = stackalloc byte[8]; System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, at.ToUnixTimeSeconds() / 30);
        var digest = HMACSHA1.HashData(key, counter); var offset = digest[^1] & 15;
        var number = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(digest.AsSpan(offset, 4)) & int.MaxValue;
        return (number % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
