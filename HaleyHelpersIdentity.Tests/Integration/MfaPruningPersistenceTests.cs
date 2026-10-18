using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class MfaPruningPersistenceTests
{
    [MariaDbFact]
    public async Task PruningRemovesOnlyUnusedRetiredMethodsAndTheirDependentData()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        using var scope = database.Scope(Guid.NewGuid());
        var identity = scope.ServiceProvider.GetRequiredService<IIdentity>();
        var first = await identity.EnsureAccountAsync(new("prune@example.test"));
        var second = await identity.EnsureAccountAsync(new("other@example.test"));
        Assert.True(first.Status); Assert.True(second.Status);
        var store = scope.ServiceProvider.GetRequiredService<IdentityStore>();
        var now = database.Clock.UtcNow;
        var pending = Guid.NewGuid();
        var active = Guid.NewGuid();
        var used = Guid.NewGuid();
        var unused = Guid.NewGuid();
        var confirmed = Guid.NewGuid();
        var referenced = Guid.NewGuid();
        var foreign = Guid.NewGuid();
        foreach (var method in new[] { pending, active, used, unused, confirmed, referenced })
            Assert.True(await store.CreateMfaMethodAsync(new(method, first.Result.UserId, MfaKind.Totp, "Test", [1], null, now), default));
        Assert.True(await store.CreateMfaMethodAsync(new(foreign, second.Result.UserId, MfaKind.Totp, "Test", [1], null, now), default));
        foreach (var method in new[] { active, used, confirmed })
            Assert.True(await store.ConfirmMfaMethodAsync(method, now, default));
        foreach (var method in new[] { used, unused, confirmed, referenced })
            Assert.True(await store.RetireMfaMethodAsync(first.Result.UserId, method, now, default));
        Assert.True(await store.RetireMfaMethodAsync(second.Result.UserId, foreign, now, default));
        // Also protect legacy confirmed records that lack a last-use timestamp.
        await database.SqlAsync("UPDATE mfa_method SET last_used_at=NULL WHERE uid=@uid", ("@uid", confirmed.ToByteArray(true)));
        await database.SqlAsync("INSERT INTO mfa_enroll (method_id,token_hash,max_attempts,expires_at) SELECT id,@hash,5,@expiry FROM mfa_method WHERE uid=@uid",
            ("@hash", new byte[32]), ("@expiry", now.AddMinutes(5).UtcDateTime), ("@uid", unused.ToByteArray(true)));
        // A reference from another ceremony must never make a bulk prune fail.
        await database.SqlAsync("INSERT INTO mfa_enroll (method_id,token_hash,replace_id,max_attempts,expires_at) SELECT m.id,@hash,r.id,5,@expiry FROM mfa_method m JOIN mfa_method r ON r.uid=@replace WHERE m.uid=@uid",
            ("@hash", Enumerable.Repeat((byte)1, 32).ToArray()), ("@expiry", now.AddMinutes(5).UtcDateTime),
            ("@replace", referenced.ToByteArray(true)), ("@uid", pending.ToByteArray(true)));

        var pruned = await scope.ServiceProvider.GetRequiredService<IMfaService>().PruneUnusedMethodsAsync(first.Result.UserId);
        Assert.True(pruned.Status); Assert.Equal(1, pruned.Result);
        Assert.Null(await store.FindMfaMethodAsync(unused, default));
        foreach (var method in new[] { pending, active, used, confirmed, referenced, foreign })
            Assert.NotNull(await store.FindMfaMethodAsync(method, default));
        Assert.Equal(0L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM mfa_enroll WHERE token_hash=@hash", ("@hash", new byte[32]))));
        Assert.Equal(6L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM mfa_data")));
        Assert.Equal(0, (await scope.ServiceProvider.GetRequiredService<IMfaService>().PruneUnusedMethodsAsync(first.Result.UserId)).Result);
    }
}
