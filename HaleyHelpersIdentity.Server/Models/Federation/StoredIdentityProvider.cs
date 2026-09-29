using Haley.Models;
namespace Haley.Models;
public sealed record StoredIdentityProvider(
    long LocalProviderId,
    Guid ProviderId,
    string Code,
    FederationProtocol Protocol,
    string Issuer,
    string DisplayName,
    IdentityRecordStatus Status,
    string Configuration,
    IReadOnlyCollection<string> AuthoritativeDomains,
    DateTimeOffset ModifiedAt,
    IReadOnlyCollection<string>? SigningCertificates = null,
    IReadOnlyCollection<string>? DiscoveryDomains = null);
