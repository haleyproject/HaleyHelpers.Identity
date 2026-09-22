namespace Haley.Models;

public sealed record VerifyPasswordResetCodeRequest(
    Guid ChallengeId,
    Guid ApplicationId,
    string Context,
    string Code,
    string? ReturnUri = null,
    string? State = null);
