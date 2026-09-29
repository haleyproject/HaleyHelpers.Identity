# Current prototype schema baseline

The current federation extraction is intended for fresh databases, as agreed for the prototype. Haley now owns the eight federation/provider tables in its canonical schema. Kida installs that base first and adds `identity_provider_tenant` with its OAuth extensions.

Do not run historical extraction migrations expecting them to produce this baseline. They remain historical artifacts for earlier versions. No new in-place migration was requested or created. Database recreation is an owner action; startup runs canonical CREATE statements and never silently ALTERs existing tables.

The renamed tables are `saml_auth_req` to `federation_request`, `saml_replay` to `federation_replay`, and `saml_handoff` to `federation_handoff`. Shared correlation uses `application_uid` and `context`; the provider's tenant association lives only in Kida's extension. Discovery and email-linking trust are separate provider-domain flags.

See [deployment](initialization.md) and [federation](FEDERATION.md) before creating the fresh environment. If existing data later needs preserving, design and review a dedicated migration against that exact deployed schema.
