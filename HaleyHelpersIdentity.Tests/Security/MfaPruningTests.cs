using Haley.Abstractions;
using Haley.Constants;
using Haley.Models;
using Haley.Security;
using Haley.Services;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class MfaPruningTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task ReportsTheStoredCountAndPropagatesAccountAndCancellation(int count)
    {
        var userId = Guid.NewGuid();
        using var cancellation = new CancellationTokenSource();
        var store = new TotpLoginStore
        {
            Pruning = (account, token) =>
            {
                Assert.Equal(userId, account);
                Assert.Equal(cancellation.Token, token);
                return ValueTask.FromResult(count);
            }
        };
        var result = await CreateService(store).PruneUnusedMethodsAsync(userId, cancellation.Token);
        Assert.True(result.Status);
        Assert.Equal(count, result.Result);
    }

    [Fact]
    public async Task EmptyAccountDoesNotReachPersistence()
    {
        var result = await CreateService(new TotpLoginStore()).PruneUnusedMethodsAsync(Guid.Empty);
        Assert.False(result.Status);
        Assert.Equal(IdentityErrorCodes.InvalidRequest, result.Key);
        Assert.Equal(400, result.Code);
    }

    [Fact]
    public async Task PersistenceFailureIsNotReportedAsSuccessfulCleanup()
    {
        var store = new TotpLoginStore { Pruning = (_, _) => throw new IOException("Simulated cleanup failure.") };
        await Assert.ThrowsAsync<IOException>(async () =>
            await CreateService(store).PruneUnusedMethodsAsync(Guid.NewGuid()));
    }

    private static MfaService CreateService(TotpLoginStore store)
    {
        var clock = new TestClock();
        return new(store, new AesGcmSecretProtector([new SecretProtectionKey("test", RandomNumberGenerator.GetBytes(32), true)]), new SecretTokenGenerator(),
            new Uuid7Generator(clock), clock, Options.Create(new IdentityServerOptions()));
    }
}
