namespace Haley.Models;

/// <summary>Ensures an account exists without creating a password or asserting email verification.</summary>
public sealed record EnsureAccountRequest(string Email, string? DisplayName = null, string? SourceReference = null, IdentityStatus InitialStatus = IdentityStatus.Active);
