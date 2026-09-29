using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json;
using System.Xml;
using Haley.Abstractions;
using Haley.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Identity.Tests;

public sealed class SamlFederationDatabaseTests
{
    [MariaDbFact]
    public async Task SignedSamlResponseUsesManagedCertificateAndCreatesOneBoundSession()
    {
        await using var database = await IdentityDatabaseFixture.CreateAsync();
        var certificateRoot = Path.Combine(Path.GetTempPath(), "identity-saml-tests", Guid.NewGuid().ToString("N"));
        var options = database.Services.GetRequiredService<IOptions<IdentityServerOptions>>().Value;
        options.Federation.CertificateRootPath = certificateRoot;
        var application = Guid.NewGuid();
        const string returnUri = "https://app.example/corporate/complete";
        const string verifier = "saml-pkce-verifier-with-at-least-forty-three-characters";
        options.AllowedReturnUris[application.ToString("D")] = [returnUri];
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=Test corporate IdP", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(database.Clock.UtcNow.AddYears(-1), database.Clock.UtcNow.AddYears(1));
        try
        {
            var certificates = database.Services.GetRequiredService<IIdentitySamlCertificateService>();
            Assert.True((await certificates.UploadAsync(new("corporate.cer", certificate.Export(X509ContentType.Cert)))).Status);
            var administration = database.Services.GetRequiredService<IIdentityProviderAdministrationService>();
            var configuration = new
            {
                ssoUrl = "https://idp.example/saml", acsUrl = "https://identity.example/identity/federation/saml/acs",
                spEntityId = "https://identity.example", allowedApplicationIds = new[] { application }
            };
            var registered = await administration.UpsertProviderAsync(null, new("corporate", FederationProtocol.Saml,
                "https://idp.example", "Corporate", JsonSerializer.Serialize(configuration), ["example.com"],
                IdentityRecordStatus.Active, ["corporate.cer"], ["example.com"]));
            Assert.True(registered.Status, registered.Message);
            using var scope = database.Scope(application);
            var federation = scope.ServiceProvider.GetRequiredService<IIdentityFederation>();
            var attempt = await federation.BeginAsync(new(application, "haley.identity", "corporate", returnUri,
                "random-application-state", Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')));
            Assert.True(attempt.Status, attempt.Message);
            var proof = new CompleteSamlAuthenticationRequest(SignedResponse(key, certificate, attempt.Result!.RequestId, database.Clock.UtcNow),
                attempt.Result.RelayState, application);
            var tampered = Encoding.UTF8.GetString(Convert.FromBase64String(proof.SamlResponse)).Replace("employee-123", "employee-999");
            Assert.False((await federation.CompleteSamlAsync(proof with { SamlResponse = Convert.ToBase64String(Encoding.UTF8.GetBytes(tampered)) })).Status);
            var completion = await federation.CompleteSamlAsync(proof);
            Assert.True(completion.Status, completion.Message);
            Assert.Equal(returnUri, completion.Result!.ReturnUri);
            Assert.False((await federation.CompleteSamlAsync(proof)).Status);
            Assert.True((await federation.RedeemAsync(new(application, completion.Result.Code, verifier))).Status);
            Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM user_session;")));
            Assert.Equal(1L, Convert.ToInt64(await database.SqlAsync("SELECT COUNT(*) FROM federation_replay;")));
        }
        finally
        {
            if (Directory.Exists(certificateRoot)) Directory.Delete(certificateRoot, true);
        }
    }

    private static string SignedResponse(RSA key, X509Certificate2 certificate, Guid attempt, DateTimeOffset now)
    {
        var responseId = "_" + Guid.NewGuid().ToString("N");
        var requestId = "_" + attempt.ToString("N");
        var issued = now.UtcDateTime.ToString("O");
        var expires = now.AddMinutes(3).UtcDateTime.ToString("O");
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.LoadXml($$"""
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{responseId}}" Version="2.0" IssueInstant="{{issued}}" Destination="https://identity.example/identity/federation/saml/acs" InResponseTo="{{requestId}}">
              <saml:Issuer>https://idp.example</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>
              <saml:Assertion ID="_{{Guid.NewGuid():N}}" Version="2.0" IssueInstant="{{issued}}">
                <saml:Issuer>https://idp.example</saml:Issuer>
                <saml:Subject><saml:NameID>employee-123</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://identity.example/identity/federation/saml/acs" InResponseTo="{{requestId}}" NotOnOrAfter="{{expires}}" /></saml:SubjectConfirmation></saml:Subject>
                <saml:Conditions NotBefore="{{issued}}" NotOnOrAfter="{{expires}}"><saml:AudienceRestriction><saml:Audience>https://identity.example</saml:Audience></saml:AudienceRestriction></saml:Conditions>
                <saml:AuthnStatement AuthnInstant="{{issued}}" />
                <saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>employee@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
              </saml:Assertion>
            </samlp:Response>
            """);
        var signed = new SignedXml(document) { SigningKey = key };
        signed.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        var reference = new Reference("#" + responseId) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signed.AddReference(reference);
        signed.KeyInfo = new KeyInfo(); signed.KeyInfo.AddClause(new KeyInfoX509Data(certificate));
        signed.ComputeSignature(); document.DocumentElement!.AppendChild(document.ImportNode(signed.GetXml(), true));
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(document.OuterXml));
    }
}
