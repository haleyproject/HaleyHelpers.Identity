namespace Haley.Models;

public sealed record CompletePasswordResetRequest(
    Guid GrantId,
    Guid ApplicationId,
    string Context,
    string NewPassword,
    string? ReturnUri = null,
    string? State = null);
