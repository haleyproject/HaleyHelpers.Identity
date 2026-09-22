namespace Haley.Abstractions;

/// <summary>Application identity established by registration or the hosting boundary.</summary>
public interface IIdentityApplicationContext
{
    Guid ApplicationId { get; }
    string? OwnerContext => null;
}
