namespace Haley.Abstractions;

/// <summary>A host-specific adapter may attach authentication without copying the remote client.</summary>
public interface IIdentityRemoteAuthentication
{
    ValueTask PrepareAsync(IRequest request, string operation, CancellationToken cancellationToken);
}
