using Haley.Abstractions;

namespace Haley.Models;
public sealed record ChangePasswordRequest(
    string Username,
    string CurrentPassword,
    string NewPassword,
    string? ClientIdentifier = null,
    string? ReturnUri = null,
    string? State = null);
