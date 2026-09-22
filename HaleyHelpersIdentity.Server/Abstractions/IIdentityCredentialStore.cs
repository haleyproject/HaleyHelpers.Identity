namespace Haley.Abstractions;

public interface IIdentityCredentialStore
{
    ValueTask<StoredUserCredential?> FindLocalCredentialAsync(string usernameNormalized, CancellationToken cancellationToken);
    ValueTask<bool> ReleaseExpiredLoginProtectionAsync(Guid userId, DateTimeOffset at, CancellationToken cancellationToken);
}
