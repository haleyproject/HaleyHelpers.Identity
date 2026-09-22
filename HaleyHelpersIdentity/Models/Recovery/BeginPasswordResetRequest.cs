namespace Haley.Models;

public sealed record BeginPasswordResetRequest(
    Guid ApplicationId,
    string Context,
    string Channel,
    string Destination,
    string? ReturnUri = null,
    string? State = null);
