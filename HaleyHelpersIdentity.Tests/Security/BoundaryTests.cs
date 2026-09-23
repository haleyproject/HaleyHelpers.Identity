using Haley.Models;
using Haley.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class BoundaryTests
{
    [Theory]
    [InlineData("AuthenticatePassword")]
    [InlineData("CreateApplicationSession")]
    [InlineData("ValidateSession")]
    [InlineData("RevokeSession")]
    [InlineData("BeginVerificationPasswordlessLogin")]
    [InlineData("CompleteVerificationPasswordlessLogin")]
    public async Task SessionOperationsRequireAnApplicationBoundKey(string operation)
    {
        var applicationId = Guid.NewGuid();
        var options = new IdentityServerOptions { TrustedNetwork = true };
        options.SessionBindingKeys[applicationId.ToString("D")] = new() { ["current"] = "current-application-secret-with-32-characters", ["previous"] = "previous-application-secret-with-32-characters" };
        var filter = new IdentityBoundaryFilter(Options.Create(options));
        var context = new DefaultHttpContext(); context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new IdentityOperationMetadata(operation, true)), "test"));
        context.Request.Headers["X-Haley-Application-Id"] = applicationId.ToString();
        var invocation = EndpointFilterInvocationContext.Create(context);
        var calls = 0;
        ValueTask<object?> Next(EndpointFilterInvocationContext _) { calls++; return ValueTask.FromResult<object?>("accepted"); }
        Assert.IsAssignableFrom<IResult>(await filter.InvokeAsync(invocation, Next)); Assert.Equal(0, calls);
        context.Request.Headers["X-Haley-Session-Key-Id"] = "current"; context.Request.Headers["X-Haley-Session-Key"] = options.SessionBindingKeys[applicationId.ToString("D")]["current"];
        Assert.Equal("accepted", await filter.InvokeAsync(invocation, Next));
        context.Request.Headers["X-Haley-Application-Id"] = Guid.NewGuid().ToString();
        Assert.IsAssignableFrom<IResult>(await filter.InvokeAsync(invocation, Next)); Assert.Equal(1, calls);
        context.Request.Headers["X-Haley-Application-Id"] = applicationId.ToString();
        context.Request.Headers["X-Haley-Session-Key-Id"] = "previous"; context.Request.Headers["X-Haley-Session-Key"] = options.SessionBindingKeys[applicationId.ToString("D")]["previous"];
        Assert.Equal("accepted", await filter.InvokeAsync(invocation, Next));
        options.SessionBindingKeys[applicationId.ToString("D")].Remove("previous");
        Assert.IsAssignableFrom<IResult>(await filter.InvokeAsync(invocation, Next)); Assert.Equal(2, calls);
    }

    [Fact]
    public async Task AccountApiRequiresExplicitTrustAndApplicationContext()
    {
        var options = new IdentityServerOptions(); var filter = new IdentityBoundaryFilter(Options.Create(options));
        var http = new DefaultHttpContext(); http.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new IdentityOperationMetadata("GetAccount", true)), "test"));
        var context = EndpointFilterInvocationContext.Create(http);
        var calls = 0;
        ValueTask<object?> Next(EndpointFilterInvocationContext _) { calls++; return ValueTask.FromResult<object?>("accepted"); }
        Assert.IsAssignableFrom<IResult>(await filter.InvokeAsync(context, Next)); options.TrustedNetwork = true;
        Assert.IsAssignableFrom<IResult>(await filter.InvokeAsync(context, Next)); Assert.Equal(0, calls);
        http.Request.Headers["X-Haley-Application-Id"] = Guid.NewGuid().ToString(); Assert.Equal("accepted", await filter.InvokeAsync(context, Next));
    }
}
