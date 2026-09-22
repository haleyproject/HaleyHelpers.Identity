using Haley.Abstractions;

namespace Haley.Models;
public sealed record VerifyMfaRequest(Guid UserId, Guid? MethodId, MfaKind Kind, string Code);
