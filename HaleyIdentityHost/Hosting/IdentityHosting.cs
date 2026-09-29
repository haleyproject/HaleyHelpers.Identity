using Haley.Abstractions;
using Haley.Extensions;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Haley.Hosting;

public static class IdentityHosting
{
    public static void ConfigureBuilder(WebApplicationBuilder builder)
    {
        builder.Configuration.AddJsonFile(Path.Combine(AppContext.BaseDirectory, "Config", "appsettings.json"), optional: true)
            .AddEnvironmentVariables();
        builder.WebHost.UseUrls(builder.Configuration["Haley:Identity:ListenUrl"] ?? "http://127.0.0.1:7430");
        builder.Services.Configure<Microsoft.AspNetCore.Routing.RouteHandlerOptions>(options => options.ThrowOnBadRequest = true);
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));
        builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
                Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
            foreach (var proxy in builder.Configuration.GetSection("Haley:Identity:TrustedProxies").Get<string[]>() ?? [])
            {
                if (!System.Net.IPAddress.TryParse(proxy, out var address)) throw new InvalidOperationException("TrustedProxies must contain IP addresses.");
                options.KnownProxies.Add(address);
            }
        });
        var gateway = new ModularGateway(logger: null!, autoConfigure: false) { ThrowCRUDExceptions = true };
        gateway.SetConfigurationRoot((IConfigurationRoot)builder.Configuration);
        gateway.Configure();
        var adapter = builder.Configuration[$"{IdentityServerOptions.SectionName}:Adapter"];
        if (string.IsNullOrWhiteSpace(adapter) || !gateway.Keys.Contains(adapter, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Configure Haley:Identity:Server:Adapter and its AdapterStrings and ConnectionStrings entries.");
        gateway.SetDefaultAdapterKey(adapter);
        builder.Services.AddSingleton<IAdapterGateway>(gateway);
        builder.Services.AddSingleton<IModularGateway>(gateway);
        builder.Services.AddHaleyIdentity(builder.Configuration, identity => identity.UseEmbedded(builder.Configuration));
        builder.Services.AddOptions<IdentityServerOptions>()
            .Validate(options => options.TrustedNetwork, "Explicitly enable TrustedNetwork only inside the intended private application boundary.")
            .Validate(options => options.SessionBindingKeys.All(app => Guid.TryParseExact(app.Key, "D", out var applicationId) && applicationId != Guid.Empty && app.Value.All(key =>
                !string.IsNullOrWhiteSpace(key.Key) && key.Value.Length is >= 32 and <= 512)), "Application session binding keys must contain 32 to 512 characters.")
            .ValidateOnStart();
        builder.Services.AddHttpContextAccessor();
        builder.AddIdentityManagement();
        builder.Services.AddScoped<IdentityAdministrationService>();
        builder.Services.Replace(ServiceDescriptor.Scoped<IIdentityApplicationContext, IdentityHttpApplicationContext>());
    }

    public static void ConfigureErrors(WebApplication app)
    {
        app.UseExceptionHandler(new ExceptionHandlerOptions
        {
            ExceptionHandler = async context =>
            {
                var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
                var status = exception is BadHttpRequestException bad ? bad.StatusCode : exception is ArgumentException or Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException ? 400 : 500;
                var traceId = System.Diagnostics.Activity.Current?.Id ?? context.TraceIdentifier;
                var detail = exception is BadHttpRequestException or ArgumentException or Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException
                    ? exception.Message : "Identity could not complete the request. Use the trace identifier to find the server diagnostic.";
                app.Logger.LogError(exception, "Identity request failed. StatusCode: {StatusCode}; TraceId: {TraceId}", status, traceId);
                context.Response.Headers.CacheControl = "no-store";
                await Results.Problem(statusCode: status, detail: detail,
                    extensions: new Dictionary<string, object?> { ["code"] = status == 400 ? "invalid_request" : "identity_failure", ["traceId"] = traceId })
                    .ExecuteAsync(context).ConfigureAwait(false);
            }
        });
    }

    public static void ConfigureApplication(WebApplication app)
    {
        app.UseForwardedHeaders();
        ConfigureErrors(app);
        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            await next(context).ConfigureAwait(false);
        });
        app.UseAdminSecurityHeaders();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.UseRateLimiter();
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.MapIdentityManagementSessions();
        app.MapIdentityManagementEndpoints();
        app.MapIdentityFederationBrowserEndpoints();
        app.MapGet("/", () => Results.Redirect("admin/"));
        app.MapGet("/admin", () => Results.Redirect("admin/"));
        app.MapFallbackToFile("/admin/{*path:nonfile}", "admin/index.html");
        app.MapGet("/health", () => Results.Ok(new { status = "ready" }));
        app.MapHaleyIdentityEndpoints();
    }
}
