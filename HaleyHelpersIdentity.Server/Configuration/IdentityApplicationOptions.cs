namespace Haley.Models;

/// <summary>Application metadata combined with its configured binding keys by application ID.</summary>
public sealed class IdentityApplicationOptions
{
    public string? DisplayName { get; set; }
    public IdentityRecordStatus? Status { get; set; }
}
