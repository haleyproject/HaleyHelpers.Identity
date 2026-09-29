namespace Haley.Models;

public sealed record AccountSessionPage(IReadOnlyCollection<AccountSessionInfo> Sessions, int Page, int PageSize, bool HasNext);
