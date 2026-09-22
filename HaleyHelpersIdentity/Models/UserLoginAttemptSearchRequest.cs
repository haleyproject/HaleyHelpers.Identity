namespace Haley.Models;

public sealed record UserLoginAttemptSearchRequest(Guid UserId, int Page = 1, int PageSize = 10);
