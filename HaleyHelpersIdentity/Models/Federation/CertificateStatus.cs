using System.Text.Json.Serialization;

namespace Haley.Models;

[Flags]
[JsonConverter(typeof(JsonNumberEnumConverter<CertificateStatus>))]
public enum CertificateStatus : int
{
    NotYetValid = 1,
    Valid = 2,
    Expired = 4,
    Invalid = 8,
}
