using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>
/// Explicit status bits. Stored lifecycle states must contain one supported bit;
/// the owning operation and database constraint define the valid states for each record.
/// Zero and conflicting combinations are not valid persisted lifecycle states.
/// </summary>
[Flags]
[JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))]
public enum IdentityStatus : int
{
    Pending = 1,
    Active = 2,
    Retired = 4,
    Locked = 8,
    Suspended = 16,
}
