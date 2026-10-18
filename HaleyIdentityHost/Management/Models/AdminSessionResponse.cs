namespace Haley.Models;

public sealed record AdminSessionResponse(bool Authenticated, bool PasswordConfigured, string AntiforgeryToken)
{
    public string IdentityName { get; init; } = "Haley Identity";
}
