namespace Haley.Models;

public sealed record BulkPasswordResetRequest(
    IReadOnlyCollection<Guid> UserIds,
    string NewPassword,
    bool RequirePasswordChange,
    string ReasonCode);
