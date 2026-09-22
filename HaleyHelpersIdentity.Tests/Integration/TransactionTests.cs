using Haley.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class TransactionTests
{
    [MariaDbFact]
    public async Task OwnerExtensionFailureRollsBackAccountSessionAndOutboxTogether()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync(new RejectSessionExtension());
        using var scope = database.Scope(Guid.NewGuid()); var client = scope.ServiceProvider.GetRequiredService<IIdentity>();
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.CreateApplicationSessionAsync(new("rollback@example.test", true)).AsTask());
        foreach (var table in new[] { "user_account", "user_session", "user_session_token", "outbox_msg" })
            Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync($"SELECT COUNT(*) FROM `{table}`")));
    }
}
