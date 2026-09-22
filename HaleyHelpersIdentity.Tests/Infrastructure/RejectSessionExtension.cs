using Haley.Abstractions;
using Haley.Models;
namespace Haley.Identity.Tests;
public sealed class RejectSessionExtension : IIdentityPersistenceExtension
{
    public ValueTask AfterOpaqueSessionCreatedAsync(long localSessionId, StartOpaqueSessionCommand command, DbExecutionLoad load) =>
        throw new InvalidOperationException("Injected owner extension failure.");
}
