using Haley.Abstractions;

namespace Haley.Models;
public sealed record RedeemFederationHandoffRequest(Guid ApplicationId, string Code, string CodeVerifier = "", MfaKind? MfaKind = null, Guid? MfaMethodId = null, string? MfaCode = null);
