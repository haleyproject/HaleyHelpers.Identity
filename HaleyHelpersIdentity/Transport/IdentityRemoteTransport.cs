using System.Text.Json;
using Haley.Enums;
using Haley.Rest;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Haley.Services;

/// <summary>All remote backends share Haley.Rest transport and the established ProblemDetails boundary.</summary>
public sealed class IdentityRemoteTransport
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly IClient _client;
    private readonly IdentityOptions _options;
    private readonly IIdentityRemoteAuthentication _authentication;

    public IdentityRemoteTransport(IOptions<IdentityOptions> options,
        IIdentityRemoteAuthentication authentication, ILogger<IdentityRemoteTransport> logger)
    {
        _options = options.Value;
        _authentication = authentication;
        var key = $"{typeof(IdentityRemoteTransport).FullName}:{_options.ApplicationId:D}:{_options.Url}";
        _client = ClientStore.Get(key) ?? ClientStore.AddClient(key, _options.Url, logger)
            ?? throw new InvalidOperationException("Haley.Rest could not create the Identity client.");
        _client.WithTimeOut(TimeSpan.FromSeconds(_options.TimeoutSeconds));
    }

    public async ValueTask<IFeedback<T>> SendAsync<T>(string operation, string path, Method method,
        object? body, CancellationToken cancellationToken)
    {
        var request = _client.WithEndPoint($"{_options.ApiPath.Trim('/')}/{path.TrimStart('/')}")
            .AddCancellationToken(cancellationToken);
        request.AddHeader("X-Haley-Application-Id", _options.ApplicationId.ToString("D"));
        if (operation is "AuthenticatePassword" or "CreateApplicationSession" or "ValidateSession" or "RevokeSession")
        {
            if (!string.IsNullOrEmpty(_options.SessionKeyId)) request.AddHeader("X-Haley-Session-Key-Id", _options.SessionKeyId);
            if (!string.IsNullOrEmpty(_options.SessionBindingSecret)) request.AddHeader("X-Haley-Session-Key", _options.SessionBindingSecret);
        }
        if (body is not null) request.WithBody(new RawBodyRequestContent(body));
        await _authentication.PrepareAsync(request, operation, cancellationToken).ConfigureAwait(false);
        var response = await request.SendAsync(method).ConfigureAwait(false);
        try
        {
            var text = (await response.AsStringResponseAsync().ConfigureAwait(false)).Content;
            if (response.IsSuccessStatusCode)
            {
                if (string.IsNullOrWhiteSpace(text))
                    return new Feedback<T>(true, "Identity operation completed.") { Code = (int)response.StatusCode, Source = "Haley.Identity" };
                return new Feedback<T>(true, "Identity operation completed.", JsonSerializer.Deserialize<T>(text, Json)!)
                    { Code = (int)response.StatusCode, Source = "Haley.Identity" };
            }
            var failure = new Feedback<T>(false, "The Identity server rejected the request.")
                { Code = (int)response.StatusCode, Source = "Haley.Identity" };
            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    using var document = JsonDocument.Parse(text);
                    var root = document.RootElement;
                    if (root.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.String) failure.Message = detail.GetString()!;
                    else if (root.TryGetProperty("title", out var title) && title.ValueKind == JsonValueKind.String) failure.Message = title.GetString()!;
                    if (root.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String) failure.Key = code.GetString()!;
                    if (root.TryGetProperty("traceId", out var trace) && trace.ValueKind == JsonValueKind.String) failure.Trace = trace.GetString()!;
                }
                catch (JsonException) { failure.Key = "invalid_error_response"; }
            }
            return failure;
        }
        finally { response.OriginalResponse?.Dispose(); }
    }

    public async ValueTask<IFeedback> SendAsync(string operation, string path, Method method, object? body, CancellationToken cancellationToken)
    {
        var result = await SendAsync<object>(operation, path, method, body, cancellationToken).ConfigureAwait(false);
        return new Feedback(result.Status, result.Message) { Key = result.Key, Code = result.Code, Source = result.Source, Trace = result.Trace };
    }
}
