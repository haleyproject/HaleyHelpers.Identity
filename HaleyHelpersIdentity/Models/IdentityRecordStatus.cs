using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>
/// Explicit status bits. Stored lifecycle states must contain one supported bit;
/// the owning operation and database constraint define the valid states for each record.
/// Zero and conflicting combinations are not valid persisted lifecycle states.
/// </summary>
[Flags]
[JsonConverter(typeof(JsonNumberEnumConverter<IdentityRecordStatus>))]
public enum IdentityRecordStatus : int
{
    Pending = 1,
    Active = 2,
    Retired = 4,
    Locked = 8,
    Suspended = 16,
    Inactive = 32,
    Revoked = 64,
    Expired = 128,
    Deprecated = 256,
    Ended = 512,
    Verified = 1024,
    Consumed = 2048,
    Cancelled = 4096,
    Exhausted = 8192,
    Staged = 16384,
    Retiring = 32768,
    Planned = 65536,
}
