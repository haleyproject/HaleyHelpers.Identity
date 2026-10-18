using System.Security.Claims;
using System.Text.Encodings.Web;
using Haley.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Haley.Identity.Tests;

public sealed class WorkflowOperatorAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(
        Request.Headers["X-Test-Operator"] != "yes" ? AuthenticateResult.NoResult() :
        AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "test-operator"), new Claim(IdentityManagementHosting.SessionClaim, "test-session")
        ], Scheme.Name)), Scheme.Name)));
}
