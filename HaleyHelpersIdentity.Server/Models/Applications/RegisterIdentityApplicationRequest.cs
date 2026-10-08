namespace Haley.Models;

public sealed record RegisterIdentityApplicationRequest(string DisplayName, Guid? ApplicationId = null);
