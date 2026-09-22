using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Haley.Security;
public sealed class SystemClock : IIdentityClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
