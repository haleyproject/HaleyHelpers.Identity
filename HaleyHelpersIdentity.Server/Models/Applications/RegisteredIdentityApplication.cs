using System.Text.Json.Serialization;

namespace Haley.Models;

/// <summary>Administrative application information. Secret values are never returned by list operations.</summary>
public sealed record RegisteredIdentityApplication(Guid ApplicationId, string DisplayName,
    [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityRecordStatus>))] IdentityRecordStatus Status,
    IReadOnlyList<string> KeyIds)
{
    /// <summary>When present, the application is disabled until its configuration is corrected.</summary>
    public string? ConfigurationError { get; init; }
}
