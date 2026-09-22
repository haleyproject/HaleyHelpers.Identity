# NuGet packaging

The repository is https://github.com/haleyproject/HaleyHelpers.Identity.

Two signed .NET 8 libraries are published together:

| Package | Initial version | Purpose |
|---|---|---|
| `Haley.Helpers.Identity` | `0.1.0` | Contracts, registration and the remote client |
| `Haley.Helpers.Identity.Server` | `0.1.0` | Embedded engine, MariaDB persistence and HTTP endpoints |

The standalone host and tests are not NuGet packages.

## Build prerequisites

Use the existing Haley workspace layout: this repository is a sibling of the
`HaleyProject` repository. That repository supplies `Haley.Version.Props`,
`HaleyProject.snk` and `Haley.png`. The signing key stays outside this repository
and must not be copied into the package or committed here. Override the
`HaleyProject` MSBuild property when the workspace uses another location.

The Server project embeds the canonical schema and seed from
`dpod9/Architecture/Haley/Identity/Database/MariaDB`. Keep the architecture
checkout alongside the Haley workspace, or set `HaleyIdentityDatabaseSource`
to that directory. Package consumers do not need the architecture checkout:
the SQL is embedded in the Server assembly. Do not maintain a second editable
copy of the schema in this repository.

Versions come from `HaleyProject/Haley.Version.Props`:
`HaleyHelpersIdentityVersion` and `HaleyHelpersIdentityServerVersion`.
The local fallback is `0.1.0`. Update both properties deliberately for subsequent
releases. NuGet versions cannot be replaced after publication.

## Build Release packages

From this repository, run:

```powershell
dotnet build HaleyHelpersIdentity/HaleyHelpersIdentity.csproj -c Release
dotnet build HaleyHelpersIdentity.Server/HaleyHelpersIdentity.Server.csproj -c Release
```

Release builds produce `.nupkg` and `.snupkg` files in each project's
`bin/Release` directory. Debug builds do not generate packages. Each package
includes the Haley icon, this repository's README, MIT license metadata,
repository URL and portable debugging symbols in the separate symbol package.

For development with the sibling Haley source repositories, build
`HaleyHelpers.Identity_Ref.sln`, or pass
`-p:HaleyIdentityUseSourceReferences=true`. The normal solution uses NuGet
references. Ensure the dependency versions in the generated `.nuspec` are
published to the destination feed before publishing Identity; a local source
build does not publish those dependencies.

## Collect and publish

1. Open `HaleyProject/NuGet Packaging` and run `CopyCorePackages.bat`.
   It now collects both Identity libraries and their symbol packages. Like the
   existing Haley workflow, it removes the original build-output copies after
   a successful copy.
2. Review the collected package files. The existing `PublishPackage.bat` pushes
   every `.nupkg` in its directory to nuget.org, so only keep packages intended
   for this release there. Use the existing NuGet authentication configuration;
   do not add an API key to source control.
3. Publish `Haley.Helpers.Identity` and then `Haley.Helpers.Identity.Server`,
   or use the existing publisher when its directory contains the intended
   release set. Keep each `.snupkg` beside its `.nupkg` so NuGet can publish the
   corresponding symbols.

Publication is an explicit release action. Building packages and running the
copy script do not publish anything. Check package and symbol availability on
the destination feed after publishing.
