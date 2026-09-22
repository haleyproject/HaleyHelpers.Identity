using Haley.Abstractions;

namespace Haley.Models;
public enum UserActivityFilter
{
    All,
    NeverLoggedIn,
    HasLoggedIn,
    PasswordChangeRequired
}
