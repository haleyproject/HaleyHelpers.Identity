namespace Haley.Models;

/// <summary>Audited email-ownership change performed inside the identity store transaction.</summary>
public sealed record SetEmailVerificationCommand(Guid UserId, Guid ContactId, bool IsVerified, string ReasonCode,
    DateTimeOffset OccurredAt, string? OperatorName = null);
