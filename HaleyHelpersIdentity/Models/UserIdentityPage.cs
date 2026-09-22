using Haley.Abstractions;

namespace Haley.Models;
public sealed record UserIdentityPage(IReadOnlyCollection<UserIdentity> Users, int Page, int PageSize, bool HasNext);
