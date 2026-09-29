using System.Security.Claims;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Haley.Hosting;

public static class IdentityManagementHosting
{
    public const string Scheme = "Identity.Admin";
    public const string Policy = "Identity.Management";
    public const string SessionClaim = "identity_admin_session";

    public static void AddIdentityManagement(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<IdentityManagementOptions>().Bind(builder.Configuration.GetSection(IdentityManagementOptions.SectionName))
            .Validate(value => value.SessionMinutes is >= 5 and <= 1440 && !string.IsNullOrWhiteSpace(value.KeyDirectory), "Management session configuration is invalid.").ValidateOnStart();
        builder.Services.AddSingleton<ManagementSessionService>();
        builder.Services.AddAdminLoginLockout(builder.Configuration, IdentityManagementOptions.SectionName);
        builder.Services.AddAdminLoginRateLimit(Policy, 10);
        builder.Services.AddAdminAntiforgery("Haley.Identity.Admin.Antiforgery", "X-CSRF-TOKEN");
        var keys = builder.Configuration[$"{IdentityManagementOptions.SectionName}:KeyDirectory"] ?? "State/AdminKeys";
        builder.Services.AddDataProtection().SetApplicationName("Haley.Identity.Admin")
            .PersistKeysToFileSystem(new DirectoryInfo(Path.GetFullPath(keys, builder.Environment.ContentRootPath)));
        builder.Services.AddAuthentication(Scheme).AddCookie(Scheme, options =>
        {
            options.Cookie.Name = "Haley.Identity.Admin.Session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.SlidingExpiration = false;
            options.Events = new CookieAuthenticationEvents
            {
                OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; },
                OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; },
                OnValidatePrincipal = async context =>
                {
                    if (!context.HttpContext.RequestServices.GetRequiredService<ManagementSessionService>().IsActive(context.Principal?.FindFirstValue(SessionClaim)))
                    {
                        context.RejectPrincipal();
                        await context.HttpContext.SignOutAsync(Scheme);
                    }
                }
            };
        });
        builder.Services.AddAuthorization(options => options.AddPolicy(Policy, policy => policy.AddAuthenticationSchemes(Scheme).RequireAuthenticatedUser().RequireClaim(SessionClaim)));
    }
}
