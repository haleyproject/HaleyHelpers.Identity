namespace Haley.Models;

public sealed class IdentitySecretOptions
{
    public string ActiveKeyId { get; set; } = string.Empty;
    public List<IdentitySecretKeyOptions> Keys { get; set; } = [];
}
