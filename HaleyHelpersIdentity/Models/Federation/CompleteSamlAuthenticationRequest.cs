using Haley.Abstractions;

namespace Haley.Models;
public sealed record CompleteSamlAuthenticationRequest(
    string SamlResponse,
    string RelayState,
    Guid? ApplicationId = null);
