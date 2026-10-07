using Haley.Utils;
using Haley.Hosting;
using Haley.Tools;

if (IdentityCredentialCli.IsCredentialCommand(args))
{
    return IdentityCredentialCli.Run(args);
}

var app = AppMaker.Get(args)
    .WithHttpsRedirection(false)
    .UseAuth(use_authentication: false, use_authorization: false)
    .WithBuilderProcessor(IdentityHosting.ConfigureBuilder)
    .WithAppProcessor(IdentityHosting.ConfigureApplication)
    .Build();
app.Run();
return 0;

public partial class Program;
