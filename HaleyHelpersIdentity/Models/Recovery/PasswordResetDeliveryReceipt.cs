namespace Haley.Models;

public sealed record PasswordResetDeliveryReceipt(
    Guid ChallengeId,
    string Channel,
    string Destination,
    string OneTimeCode,
    DateTimeOffset CodeExpiresAt,
    DateTimeOffset ResendAllowedAt,
    string ResetPath);
