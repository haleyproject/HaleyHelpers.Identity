using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record UserPageRequest(string? Query = null, [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus? Status = null, int Page = 1, int PageSize = 20, UserActivityFilter Activity = UserActivityFilter.All, UserSortOrder Sort = UserSortOrder.CreatedNewest);
