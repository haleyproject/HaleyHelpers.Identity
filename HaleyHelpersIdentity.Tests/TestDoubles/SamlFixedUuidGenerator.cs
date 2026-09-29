using Haley.Abstractions;
using Haley.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Haley.Tests;
internal sealed class SamlFixedUuidGenerator : IIdentityUuidGenerator
{
    public Guid NewUuid7() => SamlAuthenticationEdgeTests.RequestId;
}
