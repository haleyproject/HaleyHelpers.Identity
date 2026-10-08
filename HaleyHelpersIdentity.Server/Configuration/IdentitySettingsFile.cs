using System.Text.Json;
using System.Text.Json.Nodes;

namespace Haley.Utils;

/// <summary>Locked, atomic writes to the host settings file, preserving deployment symlinks.</summary>
internal sealed class IdentitySettingsFile
{
    public string FilePath { get; }

    public IdentitySettingsFile(string path)
    {
        var file = new FileInfo(Path.GetFullPath(path));
        FilePath = file.LinkTarget is null ? file.FullName : file.ResolveLinkTarget(true)!.FullName;
    }

    public byte[] ReadContent(bool requireExisting = false)
    {
        if (!File.Exists(FilePath))
        {
            if (requireExisting) throw new IOException("The identity settings file is unavailable. Existing configuration remains unchanged.");
            return "{}"u8.ToArray();
        }
        using var stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > 4 * 1024 * 1024) throw new InvalidDataException("The identity settings file exceeds the supported size.");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    public static JsonObject Parse(byte[] content)
    {
        try
        {
            var json = content.AsSpan();
            if (json.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) json = json[3..];
            return JsonNode.Parse(json, new JsonNodeOptions { PropertyNameCaseInsensitive = true },
                new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }) as JsonObject
                ?? throw new InvalidDataException("Identity settings must be a JSON object.");
        }
        catch (JsonException) { throw new InvalidDataException("Identity settings contain invalid JSON. Existing configuration remains unchanged."); }
    }

    public async Task<FileStream> AcquireLockAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var expires = DateTime.UtcNow.AddSeconds(10);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { return new FileStream(FilePath + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (DateTime.UtcNow < expires) { await Task.Delay(50, cancellationToken).ConfigureAwait(false); }
        }
    }

    public async Task WriteAtomicAsync(byte[] content, CancellationToken cancellationToken = default)
    {
        var temporary = FilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.WriteThrough };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using (var output = new FileStream(temporary, options))
            {
                await output.WriteAsync(content, cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(FilePath)) File.Replace(temporary, FilePath, null);
            else File.Move(temporary, FilePath);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
