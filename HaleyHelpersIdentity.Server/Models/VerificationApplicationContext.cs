namespace Haley.Models;

/// <summary>Immutable context for an explicitly authorized generation or proof-completion operation.</summary>
internal sealed class VerificationApplicationContext(Guid applicationId, string ownerContext) : IIdentityApplicationContext
{
    public Guid ApplicationId => applicationId;
    public string OwnerContext => ownerContext;
}
