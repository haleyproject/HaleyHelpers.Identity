namespace Haley.Models;

public sealed record TotpEnrollmentDetails(
    Guid MethodId,
    Guid UserId,
    string AccountLabel,
    string OtpauthUri,
    DateTimeOffset ExpiresAt,
    int AttemptsRemaining,
    string? ReturnUri);
