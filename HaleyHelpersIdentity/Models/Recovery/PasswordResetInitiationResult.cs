namespace Haley.Models;

public sealed record PasswordResetInitiationResult(
    bool Accepted,
    PasswordResetDeliveryReceipt? Delivery = null);
