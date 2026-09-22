namespace Haley.Models;

public sealed record PasswordChangeReceipt(string? ReturnUri = null, string? State = null);
