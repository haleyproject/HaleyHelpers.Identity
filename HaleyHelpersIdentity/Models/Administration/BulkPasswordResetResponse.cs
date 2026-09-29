namespace Haley.Models;

public sealed record BulkPasswordResetResponse(
    int TotalUsers,
    int Reset,
    int Failed,
    IReadOnlyCollection<BulkPasswordResetRowResult> Users);
