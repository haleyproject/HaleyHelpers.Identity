namespace Haley.Models;

public sealed class IdentityManagementOptions
{
    public const string SectionName = "Haley:Identity:Management";
    public bool Enabled { get; set; } = true;
    public string PasswordHash { get; set; } = string.Empty;
    public int SessionMinutes { get; set; } = 30;
    public string KeyDirectory { get; set; } = "State/AdminKeys";
}
