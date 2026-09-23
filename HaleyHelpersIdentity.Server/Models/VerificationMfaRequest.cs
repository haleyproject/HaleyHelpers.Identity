namespace Haley.Models;

public sealed record VerificationMfaRequest(Guid UserId, string Email, Guid ApplicationId, string Context,
    MfaKind? Kind, Guid? MethodId, string? Code);
