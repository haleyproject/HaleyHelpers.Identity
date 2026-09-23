namespace Haley.Models;

/// <summary>Accepted is intentionally independent of account eligibility. Do not forward Delivery to an untrusted requester.</summary>
public sealed record IdentityVerificationInitiation(bool Accepted, IdentityVerificationDelivery? Delivery = null);
