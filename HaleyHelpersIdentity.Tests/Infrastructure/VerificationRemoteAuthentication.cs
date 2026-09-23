using Haley.Abstractions;
namespace Haley.Identity.Tests;

public sealed class VerificationRemoteAuthentication : IIdentityRemoteAuthentication
{
    public List<string> Operations { get; } = [];
    public ValueTask PrepareAsync(IRequest request, string operation, CancellationToken cancellationToken)
    { Operations.Add(operation); return ValueTask.CompletedTask; }
}
