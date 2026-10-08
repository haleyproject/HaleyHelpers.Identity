using Xunit;

namespace Haley.Tests;

/// <summary>File symlink coverage runs on Linux without Windows' extra link-creation privilege.</summary>
public sealed class SymbolicLinkTheoryAttribute : TheoryAttribute
{
    public SymbolicLinkTheoryAttribute()
    {
        if (OperatingSystem.IsWindows()) Skip = "File symlink creation requires a Windows privilege; run this test on Linux.";
    }
}
