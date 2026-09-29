namespace Haley.Models;

public sealed record AdminTotpEnrollment(
    Guid MethodId,
    string Ticket,
    string QrCodeSvg,
    DateTimeOffset ExpiresAt,
    int AttemptsRemaining,
    bool ReplacesExistingMethod);
