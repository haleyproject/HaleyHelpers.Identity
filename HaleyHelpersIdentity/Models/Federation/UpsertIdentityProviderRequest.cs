using Haley.Models;
using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record UpsertIdentityProviderRequest(
    string Code,
    FederationProtocol Protocol,
    string Issuer,
    string DisplayName,
    string Configuration,
    IReadOnlyCollection<string>? AuthoritativeDomains = null,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityRecordStatus>))] IdentityRecordStatus Status = IdentityRecordStatus.Active,
    IReadOnlyCollection<string>? SigningCertificates = null,
    IReadOnlyCollection<string>? DiscoveryDomains = null);
