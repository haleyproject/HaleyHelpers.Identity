namespace Haley.Models;

/// <summary>Public login selection information. Trust configuration and keys are never returned.</summary>
public sealed record ProviderDiscovery(string Code, string DisplayName, FederationProtocol Protocol, bool IsDefault = false);
