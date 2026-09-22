using Haley.Abstractions;

namespace Haley.Models;
public sealed record ReplaceRecoveryCodesRequest(Guid UserId, int Count = 10);
