using Haley.Abstractions;

namespace Haley.Models;
public sealed record CreateLocalUserRequest(string Username, string DisplayName, string Password, bool ActivateImmediately = false, bool RequirePasswordChange = true);
