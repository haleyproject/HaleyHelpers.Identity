namespace Haley.Models;

public sealed record UserLoginAttemptInfo(
    long AttemptId,
    Guid UserId,
    Guid? ApplicationId,
    string Outcome,
    string? ReasonCode,
    DateTimeOffset OccurredAt);
