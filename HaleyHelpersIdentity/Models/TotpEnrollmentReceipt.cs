using Haley.Abstractions;

namespace Haley.Models;
public sealed record TotpEnrollmentReceipt(
    Guid MethodId,
    string Ticket,
    string BrowserPath,
    DateTimeOffset ExpiresAt);
