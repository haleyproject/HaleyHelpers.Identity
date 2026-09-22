using Haley.Abstractions;

namespace Haley.Models;
public sealed record RecoveryCodesReceipt(IReadOnlyCollection<string> Codes);
