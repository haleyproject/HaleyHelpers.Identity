using Haley.Abstractions;

namespace Haley.Models;
public sealed record FederationStart(Guid RequestId, string IdentityProviderUrl, string SamlRequest, string RelayState, DateTimeOffset ExpiresAt, string AuthorizationUrl = "", FederationProtocol Protocol = FederationProtocol.Saml);
