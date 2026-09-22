using Haley.Abstractions;

namespace Haley.Models;
public sealed record ResetUserPasswordRequest(Guid UserId, string NewPassword, bool RequirePasswordChange, string ReasonCode, string ActorReference);
