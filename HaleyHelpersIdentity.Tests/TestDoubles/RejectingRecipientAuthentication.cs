using Haley.Abstractions;

namespace Haley.Tests;

internal sealed class RejectingRecipientAuthentication : IIdentityRemoteAuthentication
{
    public ValueTask PrepareAsync(IRequest request, string operation, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Recipient completion must not request a machine token.");
}
