using Haley.Models;
namespace Haley.Models;
public sealed record FederatedIdentityLinkResult(long LocalUserId, UserIdentity Identity, bool Created, bool Linked);
