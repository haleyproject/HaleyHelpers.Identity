namespace Haley.Models;

public sealed record AdminBeginTotpEnrollment(string AccountLabel, Guid? ReplaceMethodId = null);
