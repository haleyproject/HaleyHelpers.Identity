namespace Haley.Models;
public sealed record UpdateUserProfileCommand(Guid UserId, string DisplayName, string? GivenName, string? FamilyName, string? PreferredName, string? Locale, string? TimeZone, string? AvatarUri, DateTimeOffset ModifiedAt);
