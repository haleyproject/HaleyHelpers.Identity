namespace Haley.Models;

/// <summary>A configuration problem that disables an application without exposing its credentials.</summary>
public sealed record IdentityApplicationConfigurationIssue(Guid? ApplicationId, string ConfigurationPath, string Message);
