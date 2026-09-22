using Haley.Abstractions;

namespace Haley.Models;
public sealed record BeginTotpEnrollmentRequest(
    Guid UserId,
    string AccountLabel,
    string? ReturnUri = null,
    Guid? ReplaceMethodId = null,
    Guid? ApplicationId = null,
    string? Audience = null);
