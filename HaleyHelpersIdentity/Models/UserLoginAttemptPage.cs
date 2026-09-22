namespace Haley.Models;

public sealed record UserLoginAttemptPage(
    IReadOnlyCollection<UserLoginAttemptInfo> Attempts,
    int Page,
    int PageSize,
    bool HasNext);
