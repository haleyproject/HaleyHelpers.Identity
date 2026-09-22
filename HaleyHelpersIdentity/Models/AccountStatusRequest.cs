using System.Text.Json.Serialization;
namespace Haley.Models;
public sealed record AccountStatusRequest(
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus Status, string Reason);
