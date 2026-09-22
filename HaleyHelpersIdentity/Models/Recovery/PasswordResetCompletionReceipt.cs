namespace Haley.Models;

public sealed record PasswordResetCompletionReceipt(string? ReturnUri = null, string? State = null);
