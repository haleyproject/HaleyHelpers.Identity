using Haley.Models;
using System.Text.Json.Serialization;
namespace Haley.Models;

public sealed record AdminStatusChange([property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus Status, string ReasonCode);
