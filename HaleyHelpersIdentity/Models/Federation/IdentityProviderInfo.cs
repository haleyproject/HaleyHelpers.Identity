using Haley.Models;
using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record IdentityProviderInfo(
    Guid ProviderId,
    string Code,
    FederationProtocol Protocol,
    string Issuer,
    string DisplayName,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityRecordStatus>))] IdentityRecordStatus Status,
    string Configuration,
    IReadOnlyCollection<string> AuthoritativeDomains,
    DateTimeOffset ModifiedAt,
    IReadOnlyCollection<string>? SigningCertificates = null,
    IReadOnlyCollection<string>? DiscoveryDomains = null);
