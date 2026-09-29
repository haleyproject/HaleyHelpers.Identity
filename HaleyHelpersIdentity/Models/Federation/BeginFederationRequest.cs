using Haley.Abstractions;

namespace Haley.Models;
public sealed record BeginFederationRequest(Guid ApplicationId, string Context, string ProviderCode, string ReturnUri, string State = "", string CodeChallenge = "");
