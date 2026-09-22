namespace Haley.Models;

/// <summary>Caller configuration shared by embedded and remote identity clients.</summary>
public sealed class IdentityOptions
{
    public const string SectionName = "Haley:Identity";
    public Guid ApplicationId { get; set; }
    public string Url { get; set; } = string.Empty;
    public string ApiPath { get; set; } = "api/identity";
    public string SessionKeyId { get; set; } = string.Empty;
    public string SessionBindingSecret { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 30;
}
