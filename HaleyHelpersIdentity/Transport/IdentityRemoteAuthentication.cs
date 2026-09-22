namespace Haley.Services;

/// <summary>The standalone private API has no general caller authentication.</summary>
public sealed class IdentityRemoteAuthentication : IIdentityRemoteAuthentication
{
    public ValueTask PrepareAsync(IRequest request, string operation, CancellationToken cancellationToken) => ValueTask.CompletedTask;
}
