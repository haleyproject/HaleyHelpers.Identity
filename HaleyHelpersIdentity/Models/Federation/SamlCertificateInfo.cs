using System.Text.Json.Serialization;
namespace Haley.Models;

public sealed record SamlCertificateInfo(
    string Name,
    string Subject,
    string Issuer,
    string SerialNumber,
    DateTimeOffset ValidFrom,
    DateTimeOffset ValidTo,
    string Sha256Fingerprint,
    long Size,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<CertificateStatus>))] CertificateStatus Status,
    DateTimeOffset ModifiedAt,
    IReadOnlyCollection<string> ReferencingProviders);
