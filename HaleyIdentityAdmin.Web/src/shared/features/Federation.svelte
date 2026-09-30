<script lang="ts">
  import { RecordStatus, CertificateStatus, statusLabel, statusClass, certificateStatusLabel, certificateStatusClass } from '../lib/statuses';
  import { onMount } from 'svelte';
  import { adminApi, ApiError, uuid7 } from '../lib/api';
  import { requestConfirmation } from '../lib/confirmation';
  import { showError } from '../lib/snackbar';
  import type { IdentityClientPolicy, IdentityProvider, OAuthClient, SamlCertificate } from '../lib/types';

  type Tab = 'register' | 'providers' | 'certificates' | 'policy';
  let tab: Tab = 'providers';

  let providers: IdentityProvider[] = [];
  let certificates: SamlCertificate[] = [];
  let policies: IdentityClientPolicy[] = [];
  let clients: OAuthClient[] = [];
  let clientPage = 1;
  let clientHasNext = false;
  let error = '';

  $: if (error) { showError(error, 'Federation operation failed'); error = ''; }
  let notice = '';
  let saving = false;
  let editingId: string | null = null;
  let editingPolicy = false;
  let provider = emptyProvider();
  let policy = emptyPolicy();
  let certificateFile: File | null = null;
  let certificateName = '';

  function emptyProvider() {
    return { code: '', protocol: 'Saml' as 'Saml' | 'SignedCallback', issuer: '', displayName: '', configuration: '{\n  "ssoUrl": "https://idp.example.com/saml/sso",\n  "acsUrl": "https://identity.example.com/identity/federation/saml/acs",\n  "spEntityId": "https://auth.example.com",\n  "emailClaim": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",\n  "displayNameClaim": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",\n  "validation": {\n    "validateSignature": true,\n    "validateIssuer": true,\n    "validateAudience": true,\n    "validateLifetime": true,\n    "validateDestination": true,\n    "validateRecipient": true,\n    "validateInResponseTo": true,\n    "validateReplay": true,\n    "clockSkewSeconds": 120,\n    "allowUnsafeValidation": false\n  }\n}'.replace('https://identity.example.com/identity/federation/saml/acs', adminApi.extended ? 'https://kida.example.com/api/kida/identity/federation/saml/acs' : new URL('../identity/federation/saml/acs', window.location.href).href), domains: '', discoveryDomains: '', allowedApplications: '', defaultApplications: '', contractVersion: 1, tenantId: '', status: RecordStatus.Active, signingCertificates: [] as string[] };
  }

  function selectProtocol() {
    if (provider.protocol === 'SignedCallback') provider.configuration = JSON.stringify({ authorizationUrl: 'https://corporate.example/login', callbackUrl: adminApi.extended ? 'https://kida.example.com/api/kida/identity/federation/external/callback' : new URL('../identity/federation/external/callback', window.location.href).href, audience: 'identity-bridge', keys: [{ id: 'corporate-2026', pem: '-----BEGIN PUBLIC KEY-----\nREPLACE_WITH_PUBLIC_RSA_KEY\n-----END PUBLIC KEY-----' }], maximumAssertionSeconds: 120 }, null, 2);
    else provider.configuration = emptyProvider().configuration;
  }

  function emptyPolicy() {
    return { clientId: '', resource: '', emailVerification: 'Immediate' as 'Disabled' | 'Immediate' | 'Grace', graceSeconds: 0, allowLegacyUserCreate: false, mfaRequirement: 'optional' as 'none' | 'optional' | 'required', mfaDomainRules: [] as IdentityClientPolicy['mfaDomainRules'] };
  }

  onMount(() => { void load(); });

  async function load() {
    error = '';
    try {
      const [providerRows, certificateRows, policyRows, clientRows] = await Promise.all([
        adminApi.identityProviders(), adminApi.samlCertificates(), adminApi.extended ? adminApi.identityClientPolicies() : Promise.resolve([]), adminApi.extended ? adminApi.clients(1) : Promise.resolve({ clients: [], page: 1, hasNext: false })
      ]);
      providers = providerRows;
      certificates = certificateRows;
      policies = policyRows;
      clients = clientRows.clients;
      clientPage = clientRows.page;
      clientHasNext = clientRows.hasNext;
    } catch (reason) { error = message(reason); }
  }

  async function loadClientPage(page: number) {
    if (page < 1 || (page > clientPage && !clientHasNext)) return;
    try {
      const result = await adminApi.clients(page);
      clients = result.clients;
      clientPage = result.page;
      clientHasNext = result.hasNext;
    } catch (reason) { error = message(reason); }
  }

  function edit(item: IdentityProvider) {
    const configuration = JSON.parse(item.configuration) as Record<string, unknown>;
    const allowedApplications = ((configuration.allowedApplicationIds ?? []) as string[]).join('\n');
    const defaultApplications = ((configuration.defaultForApplicationIds ?? []) as string[]).join('\n');
    const contractVersion = (configuration.contractVersion ?? 1) as number;
    delete configuration.signingCertificates;
    delete configuration.allowedApplicationIds;
    delete configuration.defaultForApplicationIds;
    delete configuration.contractVersion;
    editingId = item.providerId;
    provider = { code: item.code, protocol: item.protocol, issuer: item.issuer, displayName: item.displayName,
      configuration: JSON.stringify(configuration, null, 2), allowedApplications, defaultApplications, contractVersion, domains: item.authoritativeDomains.join('\n'), discoveryDomains: (item.discoveryDomains ?? []).join('\n'), tenantId: item.tenantId ?? '', status: item.status,
      signingCertificates: item.signingCertificates ?? [] };
    tab = 'register';
  }

  function toggleCertificate(name: string, selected: boolean) {
    provider.signingCertificates = selected
      ? [...new Set([...provider.signingCertificates, name])]
      : provider.signingCertificates.filter(value => value !== name);
  }

  function certificateStatus(name: string) {
    return certificates.find(item => item.name === name)?.status ?? 'missing';
  }

  async function uploadCertificate() {
    if (!certificateFile) return;
    saving = true; error = ''; notice = '';
    const name = (certificateName || certificateFile.name).trim().toLowerCase();
    try {
      await adminApi.uploadSamlCertificate(certificateFile, name);
      notice = `Certificate ${name} uploaded.`;
    } catch (reason) {
      if (!(reason instanceof ApiError) || reason.status !== 409 ||
          !await requestConfirmation({
            title: `Replace ${name}?`,
            message: 'Every provider referencing this logical certificate name will use the replacement immediately.',
            confirmLabel: 'Replace certificate',
            tone: 'danger'
          })) {
        error = message(reason);
        saving = false;
        return;
      }
      try {
        await adminApi.uploadSamlCertificate(certificateFile, name, true, name);
        notice = `Certificate ${name} replaced.`;
      } catch (replacementReason) {
        error = message(replacementReason);
        saving = false;
        return;
      }
    }
    certificateFile = null; certificateName = '';
    await load();
    saving = false;
  }

  async function saveProvider() {
    saving = true; error = ''; notice = '';
    try {
      const configuration = JSON.parse(provider.configuration) as Record<string, unknown>;
      if (!configuration || Array.isArray(configuration) || typeof configuration !== 'object') throw new Error('Provider configuration must be a JSON object.');
      configuration.allowedApplicationIds = [...new Set(provider.allowedApplications.split(/[\s,]+/).filter(Boolean))];
      configuration.defaultForApplicationIds = [...new Set(provider.defaultApplications.split(/[\s,]+/).filter(Boolean))];
      if (provider.protocol === 'SignedCallback') configuration.contractVersion = provider.contractVersion;
      await adminApi.saveIdentityProvider(editingId, {
        code: provider.code, protocol: provider.protocol, issuer: provider.issuer, displayName: provider.displayName,
        configuration: JSON.stringify(configuration),
        authoritativeDomains: provider.domains.split(/[\s,]+/).map(value => value.trim()).filter(Boolean),
        tenantId: adminApi.extended ? provider.tenantId || null : null, status: provider.status,
        discoveryDomains: provider.discoveryDomains.split(/[\s,]+/).map(value => value.trim()).filter(Boolean),
        signingCertificates: provider.protocol === 'Saml' ? provider.signingCertificates : []
      });
      provider = emptyProvider(); editingId = null; notice = 'Identity provider saved.'; await load();
      tab = 'providers';
    } catch (reason) { error = reason instanceof SyntaxError ? 'Provider configuration must be valid JSON.' : message(reason); }
    finally { saving = false; }
  }

  async function savePolicy() {
    saving = true; error = ''; notice = '';
    try {
      await adminApi.saveIdentityClientPolicy(policy.clientId, policy.resource, policy);
      policy = emptyPolicy(); editingPolicy = false; notice = 'Client identity policy saved.'; await load();
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
  }

  function editClientPolicy(item: IdentityClientPolicy) {
    policy = {
      clientId: item.clientId,
      resource: item.resource,
      emailVerification: item.emailVerification,
      graceSeconds: item.graceSeconds,
      allowLegacyUserCreate: item.allowLegacyUserCreate,
      mfaRequirement: item.mfaRequirement,
      mfaDomainRules: (item.mfaDomainRules ?? []).map(rule => ({ ...rule }))
    };
    editingPolicy = true;
    error = '';
    notice = '';
  }

  function addMfaDomainRule() {
    policy.mfaDomainRules = [...policy.mfaDomainRules, {
      ruleId: uuid7(), domain: '', requirement: 'required', includeSubdomains: true, priority: 0
    }];
  }

  function removeMfaDomainRule(ruleId: string) {
    policy.mfaDomainRules = policy.mfaDomainRules.filter(rule => rule.ruleId !== ruleId);
  }

  function clearClientPolicy() {
    policy = emptyPolicy();
    editingPolicy = false;
  }

  function policyClientLabel(clientId: string) {
    const client = clients.find(item => item.clientId === clientId);
    return client ? `${client.displayName} · ${client.clientIdentifier}` : clientId;
  }

  function message(reason: unknown) {
    return reason instanceof ApiError ? `${reason.message}${reason.code ? ` (${reason.code})` : ''}` : 'The operation could not be completed.';
  }
</script>

<section class="page">
  <header class="page-header">
    <div><p class="eyebrow">Identity boundary</p><h1>Federation and onboarding</h1></div>
    <div class="segmented">
      <button class:active={tab === 'providers'} onclick={() => tab = 'providers'}>Providers</button>
      <button class:active={tab === 'register'} onclick={() => { editingId = null; provider = emptyProvider(); tab = 'register'; }}>Register provider</button>
      <button class:active={tab === 'certificates'} onclick={() => tab = 'certificates'}>Certificates</button>
      {#if adminApi.extended}<button class:active={tab === 'policy'} onclick={() => tab = 'policy'}>Onboarding policy</button>{/if}
    </div>
  </header>

  {#if notice}<div class="notice success"><span>{notice}</span></div>{/if}

  {#if tab === 'providers'}
    <article class="panel table-panel">
      <div class="panel-heading"><div><p class="eyebrow">Providers</p><h3>Registered federation authorities</h3></div><small>{providers.length} providers</small></div>
      <div class="table-wrap"><table><thead><tr><th>Provider</th><th>Issuer</th><th>Certificates</th><th>Domains</th><th>Status</th><th></th></tr></thead><tbody>
        {#if providers.length === 0}
          <tr><td colspan="6"><div class="empty-state">No identity providers are registered yet.</div></td></tr>
        {:else}
          {#each providers as item}<tr><td><strong>{item.displayName}</strong><small>{item.code} · {item.protocol}</small></td><td>{item.issuer}</td><td>{#if item.protocol === 'Saml' && (item.signingCertificates?.length ?? 0) === 0}<span class="status-pill missing">missing</span>{:else if item.protocol === 'Saml'}{#each item.signingCertificates ?? [] as name}<span class="status-pill {certificateStatus(name)}">{name} · {certificateStatus(name)}</span>{/each}{:else}<small>Not applicable</small>{/if}</td><td>{item.authoritativeDomains.join(', ') || 'Proof required'}</td><td><span class="status-pill {statusClass(item.status)}">{statusLabel(item.status)}</span></td><td class="row-actions"><button onclick={() => edit(item)}>Edit</button></td></tr>{/each}
        {/if}
      </tbody></table></div>
    </article>
  {:else if tab === 'register'}
    <article class="panel form-panel">
      <div><p class="eyebrow">External trust</p><h2>{editingId ? 'Edit provider' : 'Register provider'}</h2></div>
      <div class="split"><label>Code<input bind:value={provider.code} placeholder="corporate-entra" /></label><label>Protocol<select bind:value={provider.protocol} onchange={() => selectProtocol()}><option>Saml</option><option>SignedCallback</option></select></label></div>
      <label>Display name<input bind:value={provider.displayName} /></label>
      <label>Issuer<input bind:value={provider.issuer} placeholder="https://sts.windows.net/.../" /></label>
      <label>Discovery domains <span class="optional">optional</span><textarea rows="2" bind:value={provider.discoveryDomains} placeholder="example.com"></textarea></label>
      <div class="split">
        <label>Allowed applications <span class="optional">application UUIDs, optional</span><textarea rows="2" bind:value={provider.allowedApplications} placeholder="One application UUID per line"></textarea></label>
        <label>Default for applications <span class="optional">application UUIDs, optional</span><textarea rows="2" bind:value={provider.defaultApplications} placeholder="One application UUID per line"></textarea></label>
      </div>
      <p class="form-note">An empty allowed-applications list permits any otherwise authorized application.{#if adminApi.extended} Tenant providers require an explicit allowed-applications list.{/if}</p>
      <p class="form-note">Discovery uses the entered email domain first. The application default is used when no domain matches, or when no email is supplied. Multiple domain matches require a provider choice. Each application can have one active default, and that application must be allowed to use this provider. A default does not grant access.</p>
      {#if provider.protocol === 'SignedCallback'}<label>Callback contract version<select bind:value={provider.contractVersion}><option value={1}>Version 1</option></select></label><p class="form-note">Existing version 1 integrators remain compatible. Future contract versions require an explicit configuration change.</p>{/if}
      <label>Trusted email-linking domains<textarea rows="2" bind:value={provider.domains} placeholder="example.com"></textarea></label>
      <div class="split">{#if adminApi.extended}<label>Tenant UUID <span class="optional">optional</span><input bind:value={provider.tenantId} /></label>{/if}<label>Status<select bind:value={provider.status}><option value={RecordStatus.Active}>Active</option><option value={RecordStatus.Retired}>Retired</option></select></label></div>
      {#if provider.protocol === 'Saml'}
        <fieldset>
          <legend>Trusted SAML signing certificates</legend>
          {#if certificates.length === 0}
            <div class="empty-state">Upload a public CER or PEM certificate in the Certificates tab first.</div>
          {:else}
            <div class="check-grid">
              {#each certificates as certificate}
                <label class="check"><input type="checkbox" disabled={certificate.status === CertificateStatus.Invalid} checked={provider.signingCertificates.includes(certificate.name)} onchange={(event) => toggleCertificate(certificate.name, event.currentTarget.checked)} /><span>{certificate.name}<small>{certificateStatusLabel(certificate.status)} · expires {certificate.validTo ? new Date(certificate.validTo).toLocaleDateString() : 'unknown'}</small></span></label>
              {/each}
            </div>
          {/if}
        </fieldset>
      {/if}
      <label>Provider configuration<textarea rows="12" bind:value={provider.configuration}></textarea></label>
      <p class="form-note">SAML uses <code>ssoUrl</code>, <code>acsUrl</code>, <code>spEntityId</code> and selected public certificates. Signed callbacks use <code>authorizationUrl</code>, <code>callbackUrl</code>, <code>audience</code> and named public RSA keys. Discovery does not grant email trust. Signature, lifetime, request binding and replay checks are mandatory.</p>
      <div class="modal-actions"><button class="quiet" onclick={() => { editingId = null; provider = emptyProvider(); }}>Clear</button><button class="primary" disabled={saving || (provider.protocol === 'Saml' && provider.signingCertificates.length === 0)} onclick={saveProvider}>{saving ? 'Saving…' : 'Save provider'}</button></div>
    </article>
  {:else if tab === 'certificates'}
    <article class="panel form-panel">
      <div><p class="eyebrow">Managed public trust</p><h2>SAML certificate library</h2></div>
      <p class="form-note">Only public CER and PEM certificates are accepted. JWT private keys and HTTPS certificates are managed separately and cannot be uploaded here.</p>
      <div class="split"><label>Logical filename<input bind:value={certificateName} placeholder="corporate-entra-2026.cer" /></label><label>Certificate file<input type="file" accept=".cer,.pem,application/x-x509-ca-cert" onchange={(event) => { certificateFile = event.currentTarget.files?.[0] ?? null; if (!certificateName && certificateFile) certificateName = certificateFile.name.toLowerCase(); }} /></label></div>
      <button class="primary" disabled={saving || !certificateFile} onclick={uploadCertificate}>{saving ? 'Uploading…' : 'Upload certificate'}</button>
      <div class="panel-heading" style="border-top:1px solid var(--line);padding-top:14px;margin-top:14px"><div><p class="eyebrow">Mounted volume</p><h3>Available certificates</h3></div><small>{certificates.length} certificates</small></div>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Identity</th><th>Validity</th><th>References</th></tr></thead><tbody>
        {#if certificates.length === 0}
          <tr><td colspan="4"><div class="empty-state">No managed SAML certificates are available.</div></td></tr>
        {:else}
          {#each certificates as certificate}<tr><td><strong>{certificate.name}</strong><small>{certificate.sha256Fingerprint || 'Invalid certificate'}</small></td><td>{certificate.subject || 'Unreadable'}<small>{certificate.issuer}</small></td><td><span class="status-pill {certificateStatusClass(certificate.status)}">{certificateStatusLabel(certificate.status)}</span><small>{certificate.validTo ? `Expires ${new Date(certificate.validTo).toLocaleDateString()}` : 'No validity data'}</small></td><td>{certificate.referencingProviders.join(', ') || 'Unused'}</td></tr>{/each}
        {/if}
      </tbody></table></div>
      <p class="form-note">Certificates cannot be deleted from the portal. A same-name replacement requires confirmation and is applied atomically.</p>
    </article>
  {:else}
    <article class="panel form-panel">
      <div><p class="eyebrow">Client + audience</p><h2>{editingPolicy ? 'Edit onboarding policy' : 'Onboarding policy'}</h2></div>
      <label>Client<select bind:value={policy.clientId} disabled={editingPolicy}><option value="">Select client from page {clientPage}</option>{#each clients as client}<option value={client.clientId}>{client.displayName} · {client.clientIdentifier}</option>{/each}</select></label>
      {#if !editingPolicy}<div class="mini-pagination"><button type="button" disabled={saving || clientPage <= 1} onclick={() => void loadClientPage(clientPage - 1)}>Previous clients</button><span>Page {clientPage}</span><button type="button" disabled={saving || !clientHasNext} onclick={() => void loadClientPage(clientPage + 1)}>Next clients</button></div>{/if}
      <label>User-token audience<input bind:value={policy.resource} disabled={editingPolicy} placeholder="product-api" /></label>
      <div class="split"><label>Email verification<select bind:value={policy.emailVerification}><option>Immediate</option><option>Grace</option><option>Disabled</option></select></label><label>Grace seconds<input type="number" min="0" bind:value={policy.graceSeconds} /></label></div>
      <label>MFA requirement<select bind:value={policy.mfaRequirement}><option value="none">None</option><option value="optional">Optional</option><option value="required">Required</option></select></label>
      <fieldset>
        <legend>Mailbox-domain MFA overrides</legend>
        <p class="form-note">The base requirement applies when no rule matches. Use base <strong>required</strong> plus a <strong>none</strong> exception for “all domains except…”. Subdomains match only on a dot boundary.</p>
        {#each policy.mfaDomainRules as rule (rule.ruleId)}
          <div class="split" style="align-items:end">
            <label>Domain<input bind:value={rule.domain} placeholder="example.com" /></label>
            <label>Requirement<select bind:value={rule.requirement}><option value="none">None</option><option value="optional">Optional</option><option value="required">Required</option></select></label>
          </div>
          <div class="split" style="align-items:end">
            <label>Priority<input type="number" min="0" max="65535" bind:value={rule.priority} /></label>
            <label class="check"><input type="checkbox" bind:checked={rule.includeSubdomains} /><span>Include subdomains<small><code>mail.example.com</code> also matches.</small></span></label>
          </div>
          <button class="danger-text" type="button" onclick={() => removeMfaDomainRule(rule.ruleId)}>Remove domain rule</button>
        {/each}
        <button class="quiet" type="button" onclick={addMfaDomainRule}>＋ Add domain rule</button>
      </fieldset>
      <label class="check"><input type="checkbox" bind:checked={policy.allowLegacyUserCreate} /><span>Allow legacy <code>identity.users.create</code><small>Compatibility only; prefer invite, bootstrap, or migrate.</small></span></label>
      <p class="form-note">The client and audience form the policy identity. Edit changes its verification and MFA rules; changing either key creates a separate policy.</p>
      <div class="modal-actions"><button class="quiet" disabled={saving} onclick={clearClientPolicy}>{editingPolicy ? 'Cancel edit' : 'Clear'}</button><button class="primary" disabled={saving || !policy.clientId || !policy.resource} onclick={savePolicy}>{saving ? 'Saving…' : editingPolicy ? 'Update policy' : 'Save policy'}</button></div>

      <div class="panel-heading" style="border-top:1px solid var(--line);padding-top:14px;margin-top:14px"><div><p class="eyebrow">Authoritative state</p><h3>Configured policies</h3></div><small>{policies.length} policies</small></div>
      <div class="table-wrap"><table><thead><tr><th>Client</th><th>Audience</th><th>Verification</th><th>MFA</th><th></th></tr></thead><tbody>
        {#if policies.length === 0}
          <tr><td colspan="5"><div class="empty-state">No client onboarding policies are configured yet.</div></td></tr>
        {:else}
          {#each policies as item}<tr><td><strong>{policyClientLabel(item.clientId)}</strong><small>{item.clientId}</small></td><td>{item.resource}</td><td>{item.emailVerification}{item.emailVerification === 'Grace' ? ` · ${item.graceSeconds}s` : ''}</td><td>{item.mfaRequirement}<small>{item.mfaDomainRules?.length ?? 0} domain overrides</small></td><td class="row-actions"><button onclick={() => editClientPolicy(item)}>Edit</button></td></tr>{/each}
        {/if}
      </tbody></table></div>
    </article>
  {/if}
</section>
