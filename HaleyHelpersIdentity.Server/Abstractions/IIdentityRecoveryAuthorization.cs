namespace Haley.Abstractions;
/// <summary>The host owns application authority and approved return locations, outside recovery mechanics.</summary>
public interface IIdentityRecoveryAuthorization
{
    bool TryNormalizeContext(string? value, out string normalized);
    ValueTask<bool> HasActiveResourceAuthorityAsync(Guid applicationId, string context, CancellationToken cancellationToken);
    ValueTask<bool> IsReturnUriAllowedAsync(Guid applicationId, string context, string returnUri, CancellationToken cancellationToken);
}
