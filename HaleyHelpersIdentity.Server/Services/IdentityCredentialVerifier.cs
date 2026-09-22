namespace Haley.Services;

/// <summary>Shared credential verification, including constant-cost unknown-user handling.</summary>
public sealed class IdentityCredentialVerifier(IIdentityCredentialStore store,
    IPasswordHasher hasher, IIdentityClock clock)
{
    private static readonly byte[] DummyHash = new byte[48];
    private const string DummyParameters = "{\"Iterations\":210000,\"SaltBytes\":16,\"SubkeyBytes\":32,\"Prf\":\"HMACSHA512\"}";

    public async ValueTask<StoredUserCredential?> VerifyAsync(string username, string password, CancellationToken cancellationToken)
    {
        if (!IdentityPolicy.TryNormalizeUsername(username, out var normalized) || password is null || password.Length > 1024)
            return null;
        var credential = await store.FindLocalCredentialAsync(normalized, cancellationToken).ConfigureAwait(false);
        if (credential?.Status == IdentityStatus.Locked &&
            await store.ReleaseExpiredLoginProtectionAsync(credential.UserId, clock.UtcNow, cancellationToken).ConfigureAwait(false))
            credential = await store.FindLocalCredentialAsync(normalized, cancellationToken).ConfigureAwait(false);
        var valid = credential is null
            ? hasher.Verify(password, DummyHash, "pbkdf2-sha512", DummyParameters)
            : hasher.Verify(password, credential.SecretHash, credential.Algorithm, credential.ParametersPayload);
        return valid && credential?.Status == IdentityStatus.Active ? credential : null;
    }
}
