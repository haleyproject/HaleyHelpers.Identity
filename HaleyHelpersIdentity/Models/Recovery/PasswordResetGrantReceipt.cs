namespace Haley.Models;

public sealed record PasswordResetGrantReceipt(Guid GrantId, DateTimeOffset ExpiresAt);
