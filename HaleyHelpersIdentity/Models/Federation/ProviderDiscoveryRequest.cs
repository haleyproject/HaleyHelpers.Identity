namespace Haley.Models;

public sealed record ProviderDiscoveryRequest(string EmailOrDomain = "", Guid ApplicationId = default, string Context = "");
