using Haley.Utils;
using Haley.Hosting;

var app = AppMaker.Get(args)
    .WithHttpsRedirection(false)
    .UseAuth(use_authentication: false, use_authorization: false)
    .WithBuilderProcessor(IdentityHosting.ConfigureBuilder)
    .WithAppProcessor(IdentityHosting.ConfigureApplication)
    .Build();
app.Run();

public partial class Program;
