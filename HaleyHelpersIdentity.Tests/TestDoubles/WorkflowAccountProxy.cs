using System.Reflection;
using Haley.Abstractions;
using Haley.Models;
using Microsoft.AspNetCore.Http;

namespace Haley.Identity.Tests;

public class WorkflowAccountProxy : DispatchProxy
{
    public IHttpContextAccessor Accessor { get; set; } = null!;
    public int Calls { get; private set; }
    public string? ApplicationHeader { get; private set; }
    public object? LastRequest { get; private set; }
    protected override object? Invoke(MethodInfo? method, object?[]? arguments)
    {
        Calls++;
        ApplicationHeader = Accessor.HttpContext?.Request.Headers["X-Haley-Application-Id"].ToString();
        LastRequest = arguments![0];
        if (method!.Name == nameof(IIdentity.AuthenticatePasswordAsync))
            return ValueTask.FromResult<IFeedback<OpaqueSession>>(new Feedback<OpaqueSession>(true, "Authenticated.",
                new(Guid.NewGuid(), "test-session-token", DateTimeOffset.UtcNow.AddMinutes(5))));
        if (method.Name == nameof(IIdentity.UpdateProfileAsync))
        {
            var profile = (UpdateUserProfileRequest)arguments[1]!; LastRequest = profile;
            return ValueTask.FromResult<IFeedback<UserProfile>>(new Feedback<UserProfile>(true, "Updated.",
                new((Guid)arguments[0]!, profile.DisplayName, profile.GivenName, profile.FamilyName, profile.PreferredName,
                    profile.Locale, profile.TimeZone, profile.AvatarUri, DateTimeOffset.UtcNow)));
        }
        if (method.Name == nameof(IIdentity.GetAccountAsync))
            return ValueTask.FromResult<IFeedback<UserIdentity>>(new Feedback<UserIdentity>(true, "Found.",
                new((Guid)arguments[0]!, "UUID account", IdentityStatus.Active, "username-only", DateTimeOffset.UtcNow, null, false)));
        throw new NotSupportedException(method.Name);
    }
}
