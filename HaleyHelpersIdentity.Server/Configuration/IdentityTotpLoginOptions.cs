namespace Haley.Models;

/// <summary>Explicit permission to use an enrolled authenticator as a single login factor.</summary>
public sealed class IdentityTotpLoginOptions
{
    public bool Enabled { get; set; }
    /// <summary>When empty, enabled login is available to all authorized applications.</summary>
    public List<Guid> ApplicationIds { get; set; } = [];
}
