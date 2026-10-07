using System.Net;
using Haley.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Haley.Tests;

public sealed class AdminConsoleHostingTests : IAsyncLifetime
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("identity-admin-routing-");

    public async Task InitializeAsync()
    {
        var adminRoot = Path.Combine(_root.FullName, "wwwroot", "admin");
        Directory.CreateDirectory(Path.Combine(adminRoot, "assets"));
        await File.WriteAllTextAsync(Path.Combine(adminRoot, "index.html"),
            "<!doctype html><script type=\"module\" src=\"./assets/index.js\"></script>");
        await File.WriteAllTextAsync(Path.Combine(adminRoot, "assets", "index.js"), "console.log('admin');");
        await File.WriteAllTextAsync(Path.Combine(adminRoot, "identity-admin.config.json"), "{\"apiBasePath\":\"api\"}");
    }

    public Task DisposeAsync()
    {
        _root.Delete(recursive: true);
        return Task.CompletedTask;
    }

    [Theory]
    [InlineData("")]
    [InlineData("/identity")]
    public async Task AdminDirectoryServesPageAndRelativeAssetsWithoutRedirect(string publicPrefix)
    {
        await using var app = Build(publicPrefix);
        await app.StartAsync();
        using var client = app.GetTestClient();
        var pageUri = new Uri(client.BaseAddress!, publicPrefix + "/admin/");
        using var page = await client.GetAsync(pageUri);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Null(page.Headers.Location);
        Assert.Equal("text/html", page.Content.Headers.ContentType?.MediaType);
        Assert.Contains("./assets/index.js", await page.Content.ReadAsStringAsync());

        using var script = await client.GetAsync(new Uri(pageUri, "./assets/index.js"));
        Assert.Equal(HttpStatusCode.OK, script.StatusCode);
        Assert.Equal("console.log('admin');", await script.Content.ReadAsStringAsync());

        using var config = await client.GetAsync(new Uri(pageUri, "./identity-admin.config.json"));
        Assert.Equal(HttpStatusCode.OK, config.StatusCode);
        Assert.Equal("application/json", config.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/identity")]
    public async Task SlashlessAdminRedirectsOnceAndPreservesPublicPrefixAndQuery(string publicPrefix)
    {
        await using var app = Build(publicPrefix);
        await app.StartAsync();
        using var client = app.GetTestClient();
        var requestUri = new Uri(client.BaseAddress!, publicPrefix + "/admin?view=identity");
        using var redirect = await client.GetAsync(requestUri);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        Assert.Equal("admin/?view=identity", redirect.Headers.Location?.OriginalString);

        var pageUri = new Uri(requestUri, redirect.Headers.Location!);
        Assert.Equal(publicPrefix + "/admin/", pageUri.AbsolutePath);
        using var page = await client.GetAsync(pageUri);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Null(page.Headers.Location);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/identity")]
    public async Task RootRedirectPreservesPublicPrefix(string publicPrefix)
    {
        await using var app = Build(publicPrefix);
        await app.StartAsync();
        using var client = app.GetTestClient();
        var requestUri = new Uri(client.BaseAddress!, publicPrefix + "/");
        using var redirect = await client.GetAsync(requestUri);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var pageUri = new Uri(requestUri, redirect.Headers.Location!);
        Assert.Equal(publicPrefix + "/admin/", pageUri.AbsolutePath);
        using var page = await client.GetAsync(pageUri);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/identity")]
    public async Task MissingAssetReturnsNotFound(string publicPrefix)
    {
        await using var app = Build(publicPrefix);
        await app.StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.GetAsync(publicPrefix + "/admin/assets/missing.js");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private WebApplication Build(string publicPrefix)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = _root.FullName,
            WebRootPath = Path.Combine(_root.FullName, "wwwroot"),
            EnvironmentName = "Production"
        });
        builder.Logging.ClearProviders();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        if (publicPrefix.Length > 0)
        {
            // Simulate a reverse proxy stripping a prefix without telling the host about it.
            app.Use(async (context, next) =>
            {
                if (!context.Request.Path.StartsWithSegments(publicPrefix, out var remaining))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }
                context.Request.Path = remaining;
                await next();
            });
        }
        app.UseRouting();
        IdentityHosting.ConfigureAdminConsole(app);
        return app;
    }
}
