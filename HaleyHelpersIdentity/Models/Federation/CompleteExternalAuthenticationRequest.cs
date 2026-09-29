namespace Haley.Models;

/// <summary>A corporate backend's signed assertion, bound to one outstanding browser attempt.</summary>
public sealed record CompleteExternalAuthenticationRequest(string Attempt, string Assertion, Guid? ApplicationId = null);
