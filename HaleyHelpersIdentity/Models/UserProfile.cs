using Haley.Abstractions;

namespace Haley.Models;
/// <summary>
/// The small, platform-wide profile owned by Kida Identity. Product, employment,
/// tenant, and authorization data deliberately do not belong in this contract.
/// </summary>
public sealed record UserProfile(Guid UserId, string DisplayName, string? GivenName, string? FamilyName, string? PreferredName, string? Locale, string? TimeZone, string? AvatarUri, DateTimeOffset ModifiedAt);
