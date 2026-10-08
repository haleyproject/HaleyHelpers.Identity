namespace Haley.Models;

/// <summary>A newly issued application credential, returned only by registration or rotation.</summary>
public sealed record IdentityApplicationCredential(Guid ApplicationId, string SessionKeyId, string SessionBindingSecret);
