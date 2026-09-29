using System.Net;
using System.Security.Cryptography;

namespace Haley.Models;

/// <summary>Returns a one-use login handoff to the validated application callback through the browser.</summary>
public sealed record FederationHandoffPage(string Html, string ContentSecurityPolicy)
{
    public static FederationHandoffPage Create(string returnUri, string code, string state, string codeField = "identity_code")
    {
        if (!Uri.TryCreate(returnUri, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) || codeField is not ("identity_code" or "kida_code"))
            throw new ArgumentException("An approved callback URI and handoff field are required.");
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
        var policy = $"default-src 'none'; script-src 'nonce-{nonce}'; form-action {uri.GetLeftPart(UriPartial.Authority)}; base-uri 'none'; frame-ancestors 'none'";
        return new($"""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Completing sign-in</title></head>
            <body><form id="handoff" method="post" action="{WebUtility.HtmlEncode(returnUri)}">
            <input type="hidden" name="{codeField}" value="{WebUtility.HtmlEncode(code)}">
            <input type="hidden" name="state" value="{WebUtility.HtmlEncode(state)}">
            <noscript><button type="submit">Continue sign-in</button></noscript></form>
            <script nonce="{nonce}">document.getElementById('handoff').submit();</script></body></html>
            """, policy);
    }
}
