using Haley.Models;

namespace Haley.Models;

public sealed record CreateAdminVerificationRequest(Guid ApplicationId, BeginIdentityVerificationRequest Request, string PageUrl);
