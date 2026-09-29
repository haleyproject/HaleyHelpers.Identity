namespace Haley.Models;

public sealed record BulkPasswordResetRowResult(Guid UserId, bool Succeeded, string? ErrorCode = null);
