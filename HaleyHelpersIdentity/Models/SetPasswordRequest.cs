namespace Haley.Models;

public sealed record SetPasswordRequest(string Password, bool RequirePasswordChange = false);
