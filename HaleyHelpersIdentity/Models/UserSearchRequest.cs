using System.Text.Json.Serialization;
using Haley.Abstractions;

namespace Haley.Models;
public sealed record UserSearchRequest(string? Query = null, [property: JsonConverter(typeof(JsonNumberEnumConverter<IdentityStatus>))] IdentityStatus? Status = null, int Limit = 100, Guid? AfterUserId = null);
