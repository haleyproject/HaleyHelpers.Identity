using System.Security.Cryptography;
using System.Text;
using Haley.Abstractions;
using Haley.Security;
namespace Haley.Security;

internal sealed class SamlReplayStore(
    IIdentityFederationStore store,
    long localProviderId,
    IIdentityClock clock) : ISamlReplayValidator
{
    public ValueTask<bool> TryConsumeAsync(
        string responseId,
        string assertionId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default) =>
        store.TryConsumeFederationReplayAsync(
            localProviderId,
            SHA256.HashData(Encoding.UTF8.GetBytes(responseId)),
            SHA256.HashData(Encoding.UTF8.GetBytes(assertionId)),
            expiresAt,
            clock.UtcNow,
            cancellationToken);
}
