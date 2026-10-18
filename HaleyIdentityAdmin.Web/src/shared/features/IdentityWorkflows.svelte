<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { adminApi, uuid7 } from '../lib/api';
  import { copyText } from '../lib/clipboard';
  import { requestConfirmation } from '../lib/confirmation';
  import { RecordStatus, statusLabel } from '../lib/statuses';
  import { VerificationPurpose, VerificationProofKind } from '../lib/types';
  import type { IdentityWorkflowView, IdentityWorkflowSettings, IdentityWorkflowApplication, UserIdentity, UserProfile, MfaMethod, VerificationDelivery, VerificationLink, VerificationCompletion, VerificationSubmission, UserOpaqueSession, UserSessionValidation } from '../lib/types';

  // Embedded inside the account page (Users.svelte). The account is global; the application and
  // audience are only an execution context for actions that run on an application's behalf, so
  // they are picked once here and kept by the parent while the operator moves between sections.
  export let view: IdentityWorkflowView;
  export let account: UserIdentity | null = null;
  export let applications: IdentityWorkflowApplication[] = [];
  export let applicationId = '';
  export let resource = '';
  export let settings: IdentityWorkflowSettings | null = null;
  export let onVerificationChanged: () => Promise<void> = async () => {};

  let error = '';
  let notice = '';
  let busy = false;
  let now = Date.now();
  let timer: ReturnType<typeof setInterval>;

  // Account-derived details.
  let detailsKey = '';
  let detailsVersion = 0;
  let emailContacts: import('../lib/types').AccountEmailContact[] = [];
  let contactsLoading = false;
  let accountDetailsRequest: ReturnType<typeof fetchAccountDetails> | null = null;
  let methods: MfaMethod[] = [];
  let profile = emptyProfile();

  // Verification.
  let email = '';
  let purpose = VerificationPurpose.EmailVerification;
  let proofKind = VerificationProofKind.NumericCode;
  let validitySeconds = settings?.codeValiditySeconds ?? 300;
  let recipientPageUrl = '';
  let delivery: VerificationDelivery | null = null;
  let link: VerificationLink | null = null;
  let issuedRecipientLink = '';
  let verifier = '';
  let completionPassword = '';
  let completionConfirmation = '';
  let completion: VerificationCompletion | null = null;

  // Recovery codes and factors.
  let recoveryCount = 10;
  let recoveryCodes: string[] = [];
  let mfaKind: 'Totp' | 'RecoveryCode' = 'Totp';
  let mfaCode = '';
  let mfaMethodId = '';

  // Sessions and passwords.
  let authenticationMode: 'password' | 'totp' | 'application' = 'password';
  let password = '';
  let currentPassword = '';
  let replacementPassword = '';
  let replacementConfirmation = '';
  let session: UserOpaqueSession | null = null;
  let sessionToken = '';
  let sessionValidation: UserSessionValidation | null = null;

  const profileFields: Array<{ key: 'givenName' | 'familyName' | 'preferredName' | 'locale' | 'timeZone' | 'avatarUri'; label: string }> = [
    { key: 'givenName', label: 'Given name' }, { key: 'familyName', label: 'Family name' }, { key: 'preferredName', label: 'Preferred name' },
    { key: 'locale', label: 'Locale' }, { key: 'timeZone', label: 'Time zone' }, { key: 'avatarUri', label: 'Avatar URL' }
  ];
  const purposes = [
    { value: VerificationPurpose.EmailVerification, label: 'Verify email', detail: 'Proves mailbox ownership. Account status stays unchanged.' },
    { value: VerificationPurpose.Onboarding, label: 'Activate through onboarding', detail: 'Verifies the email and activates a Pending account. An initial password may be required.' },
    { value: VerificationPurpose.PasswordReset, label: 'Recover password', detail: 'Requires an Active account with a verified, recovery-enabled email and an existing password.' },
    { value: VerificationPurpose.PasswordlessLogin, label: 'Passwordless sign-in', detail: 'Requires an Active, verified account. Client MFA policy still applies.' }
  ];

  $: context = { applicationId, resource };
  $: needsApplication = view === 'verification' || view === 'authentication';
  $: hasApplication = !!applicationId && !!resource;
  $: applicationLabel = adminApi.extended ? 'Client' : 'Application';
  $: selectedApplication = applications.find(item => item.applicationId === applicationId) ?? null;
  $: defaultRecipientPageUrl = settings?.applicationPageUrls?.[applicationId] ?? settings?.pageUrl ?? '';
  $: recipientUrl = link ? issuedRecipientLink && !recipientPageUrl ? issuedRecipientLink : safeRecipientUrl(link, recipientPageUrl || defaultRecipientPageUrl) : '';
  $: maximumLifetime = proofKind === VerificationProofKind.NumericCode ? settings?.maximumCodeValiditySeconds ?? 3600 : settings?.maximumTokenValiditySeconds ?? 604800;
  $: requiresPassword = purpose === VerificationPurpose.PasswordReset || purpose === VerificationPurpose.Onboarding && (account?.passwordChangeRequired ?? true);
  $: expired = delivery !== null && now >= new Date(delivery.expiresAt).getTime();
  $: resendWaiting = delivery !== null && now < new Date(delivery.resendAllowedAt).getTime();
  $: activeMethods = methods.filter(method => method.status === RecordStatus.Active && method.kind === 'Totp');
  $: loginIdentifier = account?.username?.trim() || email.trim();
  $: canOperate = !!account && hasApplication && !!(view === 'authentication' && authenticationMode === 'password' ? loginIdentifier : email.trim()) && !busy && !contactsLoading;
  $: generationBlockedReason = !hasApplication ? `Select a ${applicationLabel.toLowerCase()}${adminApi.extended ? ' and audience' : ''}.` :
    contactsLoading ? 'Loading the account email contacts...' : !email.trim() ? 'Select or enter a recorded email address for this account.' : '';
  $: selectedEmailContact = emailContacts.find(contact => contact.email === email);
  $: emailInfo = selectedEmailContact && account ? { userId: account.userId, email: selectedEmailContact.email,
    verifiedAt: selectedEmailContact.verifiedAt, isVerified: selectedEmailContact.isVerified, recoveryEnabled: selectedEmailContact.recoveryEnabled } : null;
  $: void loadDetails(account?.userId ?? '', applicationId, resource);

  onMount(() => { timer = setInterval(() => now = Date.now(), 1000); });
  onDestroy(() => clearInterval(timer));

  function emptyProfile() { return { displayName: '', givenName: '', familyName: '', preferredName: '', locale: '', timeZone: '', avatarUri: '' }; }
  async function fetchAccountDetails(userId: string) {
    const [details, factors, contacts] = await Promise.all([adminApi.userProfile(userId), adminApi.userMfa(userId), adminApi.userEmailContacts(userId)]);
    return { details, factors, contacts };
  }

  async function loadDetails(userId: string, application: string, audience: string) {
    const key = `${userId}|${application}|${audience}`;
    if (key === detailsKey) return;
    const accountChanged = !detailsKey.startsWith(`${userId}|`);
    detailsKey = key;
    const version = ++detailsVersion;
    if (accountChanged) { clearSecrets(); emailContacts = []; methods = []; profile = emptyProfile(); }
    if (!userId || !account) { emailContacts = []; methods = []; profile = emptyProfile(); email = ''; contactsLoading = false; accountDetailsRequest = null; return; }
    if (accountChanged || accountDetailsRequest === null) {
      email = account.username?.includes('@') ? account.username : '';
      contactsLoading = true;
      accountDetailsRequest = fetchAccountDetails(userId);
    }
    try {
      // Application context can arrive while account details are loading. Every
      // context change awaits the same request so its response cannot be discarded.
      const { details, factors, contacts } = await accountDetailsRequest;
      if (version !== detailsVersion) return;
      setProfile(details);
      methods = factors;
      emailContacts = contacts;
      email = contacts.find(contact => contact.email.toLowerCase() === email.toLowerCase())?.email ??
        contacts.find(contact => !contact.isVerified)?.email ?? contacts[0]?.email ?? email;
      contactsLoading = false;
    } catch (reason) {
      if (version === detailsVersion) { contactsLoading = false; accountDetailsRequest = null; error = message(reason); }
    }
  }

  function clearSecrets() {
    delivery = null; link = null; issuedRecipientLink = ''; verifier = ''; completion = null;
    completionPassword = ''; completionConfirmation = ''; recoveryCodes = []; session = null; sessionToken = ''; sessionValidation = null;
    password = ''; currentPassword = ''; replacementPassword = ''; replacementConfirmation = ''; mfaCode = ''; mfaMethodId = '';
  }
  function changeApplication() {
    const selected = applications.find(item => item.applicationId === applicationId);
    resource = adminApi.extended ? selected?.resources[0] ?? '' : 'haley.identity';
    recipientPageUrl = '';
    resetProof();
  }
  function safeRecipientUrl(value: VerificationLink, pageUrl: string) {
    try { return adminApi.verificationLink(value, pageUrl); } catch { return ''; }
  }
  function resetProof() { delivery = null; link = null; completion = null; verifier = ''; completionPassword = ''; completionConfirmation = ''; error = ''; notice = ''; }
  function changeProofKind() { resetProof(); validitySeconds = proofKind === VerificationProofKind.NumericCode ? settings?.codeValiditySeconds ?? 300 : settings?.activationLinkSeconds ?? 86400; }
  function message(reason: unknown) { return reason instanceof Error ? reason.message : 'The identity operation failed.'; }
  function date(value: string | null) { return value ? new Date(value).toLocaleString() : 'Not verified'; }
  async function copy(value: string, label: string) { if (await copyText(value)) notice = `${label} copied.`; else error = `Could not copy ${label.toLowerCase()}.`; }
  function factors() { return mfaCode.trim() ? { mfaKind, mfaCode: mfaCode.trim(), ...(mfaMethodId ? { mfaMethodId } : {}) } : {}; }
  function setProfile(value: UserProfile) { profile = { displayName: value.displayName, givenName: value.givenName ?? '', familyName: value.familyName ?? '', preferredName: value.preferredName ?? '', locale: value.locale ?? '', timeZone: value.timeZone ?? '', avatarUri: value.avatarUri ?? '' }; }

  async function beginVerification() {
    busy = true; error = ''; notice = ''; completion = null; verifier = ''; completionPassword = ''; completionConfirmation = '';
    try {
      const state = uuid7();
      const page = adminApi.verificationPageUrl(recipientPageUrl || defaultRecipientPageUrl).href;
      const result = await adminApi.beginWorkflowVerification(context, { email: email.trim(), purpose, proofKind, validitySeconds, context: state }, page);
      if (!result.delivery) { notice = 'No challenge was issued. Check the account state, email recovery eligibility, and resend cooldown.'; return; }
      delivery = result.delivery;
      link = { ...context, challengeId: delivery.challengeId, purpose: delivery.purpose, proofKind: delivery.proofKind, context: state, email: delivery.destination, expiresAt: delivery.expiresAt,
        requiresPassword, ...(delivery.proofKind === VerificationProofKind.LinkToken ? { verifier: delivery.verifier } : {}) };
      issuedRecipientLink = result.link ?? '';
      notice = 'Challenge created. Copy the recipient link and deliver it manually. For a code challenge, deliver the code too.';
    } catch (reason) { error = message(reason); } finally { busy = false; }
  }
  async function completeVerification() {
    if (!link) return;
    if (requiresPassword && completionPassword !== completionConfirmation) { error = 'The new passwords do not match.'; return; }
    busy = true; error = ''; notice = '';
    try {
      const submission: VerificationSubmission = { challengeId: link.challengeId, purpose: link.purpose, proofKind: link.proofKind, context: link.context, verifier: verifier.trim(),
        ...(completionPassword ? { newPassword: completionPassword } : {}), ...(link.purpose === VerificationPurpose.PasswordlessLogin ? factors() : {}) };
      completion = await adminApi.runIdentityWorkflow<VerificationCompletion>(context, 'verification/completion', submission);
      if (account) account = await adminApi.userAccount(account.userId);
      if (completion.session) { session = completion.session; sessionToken = session.token; }
      notice = 'Verification completed. The proof has been consumed.'; delivery = null; link = null;
      if (account) emailContacts = await adminApi.userEmailContacts(account.userId);
      accountDetailsRequest = null;
      await onVerificationChanged();
    } catch (reason) { error = message(reason); }
    finally { busy = false; verifier = ''; completionPassword = ''; completionConfirmation = ''; mfaCode = ''; }
  }
  async function replaceCodes() {
    if (!account || !await requestConfirmation({ title: 'Replace recovery codes?', message: 'Previously issued recovery codes will stop working. Save the new codes before leaving this screen.', confirmLabel: 'Replace codes', tone: 'danger' })) return;
    busy = true; error = ''; recoveryCodes = [];
    try { recoveryCodes = (await adminApi.replaceUserRecoveryCodes(account.userId, recoveryCount)).codes; notice = 'New recovery codes are shown once. Previous codes have been replaced.'; }
    catch (reason) { error = message(reason); } finally { busy = false; }
  }
  async function verifyFactor() {
    if (!account) return;
    busy = true; error = '';
    try { await adminApi.verifyUserMfa(account.userId, mfaKind, mfaCode.trim(), mfaMethodId || undefined); notice = `${mfaKind === 'RecoveryCode' ? 'Recovery code' : 'Authenticator code'} verified and consumed.`; }
    catch (reason) { error = message(reason); } finally { busy = false; mfaCode = ''; }
  }
  async function authenticate() {
    if (authenticationMode === 'application' && !await requestConfirmation({ title: 'Assert application authentication?', message: 'This creates a real session for an account that the selected application has already authenticated. Required MFA is still checked.', confirmLabel: 'Create session' })) return;
    busy = true; error = ''; notice = ''; session = null; sessionValidation = null; sessionToken = '';
    try {
      if (authenticationMode === 'password') session = await adminApi.runIdentityWorkflow<UserOpaqueSession>(context, 'sessions/password', { username: loginIdentifier, password, ...factors() });
      else if (authenticationMode === 'totp') session = await adminApi.runIdentityWorkflow<UserOpaqueSession>(context, 'sessions/totp', { email: email.trim(), code: mfaCode.trim(), kind: mfaKind, ...(mfaMethodId ? { methodId: mfaMethodId } : {}) });
      else session = await adminApi.runIdentityWorkflow<UserOpaqueSession>(context, 'sessions/application', { email: email.trim(), createIfMissing: false, ...factors() });
      sessionToken = session.token; notice = 'A user session was issued for the selected application and audience.';
    } catch (reason) { error = message(reason); } finally { busy = false; password = ''; mfaCode = ''; }
  }
  async function validateSession() {
    busy = true; error = ''; sessionValidation = null;
    try { sessionValidation = await adminApi.runIdentityWorkflow<UserSessionValidation>(context, 'sessions/validation', { token: sessionToken.trim() }); notice = 'The user session is valid for this application and audience.'; }
    catch (reason) { error = message(reason); } finally { busy = false; }
  }
  async function revokeSession() {
    busy = true; error = '';
    try { await adminApi.runIdentityWorkflow<void>(context, 'sessions/revocation', { token: sessionToken.trim() }); session = null; sessionValidation = null; sessionToken = ''; notice = 'The user session was revoked.'; }
    catch (reason) { error = message(reason); } finally { busy = false; }
  }
  async function changePassword() {
    if (replacementPassword !== replacementConfirmation) { error = 'The new passwords do not match.'; return; }
    busy = true; error = '';
    try { await adminApi.runIdentityWorkflow<void>(context, 'password/change', { username: loginIdentifier, currentPassword, newPassword: replacementPassword }); notice = 'Password changed using the current-password proof.'; }
    catch (reason) { error = message(reason); } finally { busy = false; currentPassword = ''; replacementPassword = ''; replacementConfirmation = ''; }
  }
  async function saveProfile() {
    if (!account) return;
    busy = true; error = '';
    try {
      const value = await adminApi.updateUserProfile(account.userId, { displayName: profile.displayName, givenName: profile.givenName.trim() || null, familyName: profile.familyName.trim() || null,
        preferredName: profile.preferredName.trim() || null, locale: profile.locale.trim() || null, timeZone: profile.timeZone.trim() || null, avatarUri: profile.avatarUri.trim() || null });
      setProfile(value); account = { ...account, displayName: value.displayName }; notice = 'Profile updated.';
    } catch (reason) { error = message(reason); } finally { busy = false; }
  }
</script>

{#if error}<div class="notice error" role="alert"><strong>Failed</strong><span>{error}</span><button aria-label="Dismiss" onclick={() => error = ''}>×</button></div>{/if}
{#if notice}<div class="notice success" role="status"><strong>Done</strong><span>{notice}</span><button aria-label="Dismiss" onclick={() => notice = ''}>×</button></div>{/if}

{#if needsApplication}
  <div class="panel compact acting-as">
    <div class="acting-copy"><strong>Acting as {applicationLabel.toLowerCase()}</strong><small>{view === 'verification' ? 'Challenges are bound to this application and its onboarding policy.' : 'Sessions are issued for this application and audience.'}</small></div>
    <label>{applicationLabel}<select bind:value={applicationId} onchange={changeApplication} disabled={busy}><option value="">Select</option>{#each applications as item}<option value={item.applicationId}>{item.name} ({item.code})</option>{/each}</select></label>
    {#if adminApi.extended}<label>Audience<select bind:value={resource} onchange={resetProof} disabled={busy || !selectedApplication}><option value="">Select</option>{#each selectedApplication?.resources ?? [] as audience}<option value={audience}>{audience}</option>{/each}</select></label>{/if}
    {#if emailInfo}<span class="header-status" class:unverified={!emailInfo.isVerified}><span></span>{emailInfo.isVerified ? 'Email verified' : 'Email not verified'} · recovery {emailInfo.recoveryEnabled ? 'on' : 'off'}</span>{/if}
  </div>
{/if}

{#if view === 'verification'}
  <div class="two-column workflow-columns">
    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Step 1</p><h3>Create a challenge</h3></div></div>
      <form onsubmit={(event) => { event.preventDefault(); void beginVerification(); }}>
        {#if emailContacts.length > 0}<label>Account email<select bind:value={email} onchange={resetProof} disabled={busy || contactsLoading} required>{#each emailContacts as contact}<option value={contact.email}>{contact.email}{contact.isVerified ? ' · verified' : ' · not verified'}</option>{/each}</select></label>
        {:else}<label>Account email<input type="email" bind:value={email} autocomplete="off" required disabled={busy || contactsLoading} placeholder="person@example.com" /></label>
          {#if !contactsLoading && !error}<p class="form-note">No active email contact was found. The address must be recorded on this account before a challenge can be issued.</p>{/if}{/if}
        <label>Purpose<select bind:value={purpose} onchange={resetProof} disabled={busy}>{#each purposes as item}<option value={item.value}>{item.label}</option>{/each}</select></label>
        <p class="form-note">{purposes.find(item => item.value === purpose)?.detail}</p>
        {#if emailInfo?.isVerified && purpose === VerificationPurpose.EmailVerification}<p class="form-note">This email is already verified. You can issue and complete another challenge to simulate the verification flow.</p>{/if}
        <div class="split">
          <label>Proof<select bind:value={proofKind} onchange={changeProofKind} disabled={busy}><option value={VerificationProofKind.NumericCode}>Email code</option><option value={VerificationProofKind.LinkToken}>Email link</option></select></label>
          <label>Validity in seconds<input type="number" min="60" max={maximumLifetime} bind:value={validitySeconds} required disabled={busy} /></label>
        </div>
        <label>Recipient page URL <span class="optional">Optional</span><input type="url" bind:value={recipientPageUrl} placeholder={defaultRecipientPageUrl || 'Identity-hosted verification page'} disabled={busy} /></label>
        <p class="form-note">Up to {maximumLifetime} seconds for this proof. Codes are {settings?.codeLength ?? 6} digits with {settings?.maximumAttempts ?? 5} attempts. Leave the page URL empty to use the configured or identity-hosted page.</p>
        <div class="modal-actions"><button class="primary" disabled={!canOperate || resendWaiting}>{busy ? 'Working…' : resendWaiting ? 'Waiting for resend cooldown' : 'Generate code or link'}</button></div>
        {#if generationBlockedReason}<p class="form-note" role="status">{generationBlockedReason}</p>{/if}
      </form>
      {#if delivery && link}
        <dl class="secret-details">
          {#if proofKind === VerificationProofKind.NumericCode}<div><dt>One-time email code</dt><dd class="secret-box proof-code"><code>{delivery.verifier}</code></dd></div>{/if}
          <div><dt>Recipient link</dt><dd><textarea readonly value={recipientUrl} rows="3"></textarea>{#if !recipientUrl}<small>Enter a valid recipient-page URL to prepare the link.</small>{/if}</dd></div>
          <div><dt>Delivery</dt><dd>Deliver manually to <strong>{delivery.destination}</strong>. Expires {date(delivery.expiresAt)}{expired ? ' · expired' : ''}. Resend allowed {date(delivery.resendAllowedAt)}.</dd></div>
        </dl>
        <div class="row-actions">{#if proofKind === VerificationProofKind.NumericCode}<button type="button" disabled={expired} onclick={() => void copy(delivery!.verifier, 'Code')}>Copy code</button>{/if}<button type="button" disabled={expired || !recipientUrl} onclick={() => void copy(recipientUrl, 'Recipient link')}>Copy recipient link</button></div>
      {/if}
    </section>

    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Step 2</p><h3>Complete with proof</h3></div></div>
      <p class="form-note">Recipients normally use the link without an admin login. You can also complete the challenge here with their code or link token.</p>
      {#if link}
        <form onsubmit={(event) => { event.preventDefault(); void completeVerification(); }}>
          <label>{link.proofKind === VerificationProofKind.NumericCode ? 'Received code' : 'Received link token'}<input type="password" bind:value={verifier} autocomplete="off" required disabled={busy || expired} /></label>
          {#if requiresPassword}<div class="split"><label>New password<input type="password" bind:value={completionPassword} autocomplete="new-password" minlength={settings?.minimumPasswordLength ?? 9} maxlength={settings?.maximumPasswordLength ?? 1024} required /></label><label>Confirm password<input type="password" bind:value={completionConfirmation} autocomplete="new-password" required /></label></div>{/if}
          {#if purpose === VerificationPurpose.PasswordlessLogin}<div class="split"><label>Second factor<select bind:value={mfaKind}><option value="Totp">Authenticator</option><option value="RecoveryCode">Recovery code</option></select></label><label>Second-factor code<input type="password" bind:value={mfaCode} autocomplete="off" /></label></div>{/if}
          <div class="modal-actions"><button class="primary" disabled={busy || expired || !verifier.trim()}>Complete verification</button></div>
        </form>
      {:else}
        <div class="empty-state"><strong>No open challenge</strong><p>Create a challenge first to prepare its recipient link and completion form.</p></div>
      {/if}
      {#if completion}
        <div class="notice success"><strong>Completed</strong><span>Account {statusLabel(completion.accountStatus)} · email {completion.emailVerified ? 'verified' : 'unverified'}{completion.session ? ` · session expires ${date(completion.session.expiresAt)}` : ''}</span>{#if completion.session}<button type="button" class="inline" onclick={() => void copy(completion!.session!.token, 'User session token')}>Copy token</button>{/if}</div>
      {/if}
    </section>
  </div>

{:else if view === 'recovery'}
  <div class="two-column workflow-columns">
    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Recovery</p><h3>Replace recovery codes</h3></div></div>
      <p class="form-note danger-note">Replacing codes invalidates the previous set. The new values are shown once.</p>
      <form onsubmit={(event) => { event.preventDefault(); void replaceCodes(); }}>
        <label>Number of codes<input type="number" bind:value={recoveryCount} min="5" max="20" required disabled={busy} /></label>
        <div class="modal-actions"><button class="primary" disabled={!account || busy}>Generate replacement codes</button></div>
      </form>
      {#if recoveryCodes.length}
        <div class="recovery-grid">{#each recoveryCodes as code}<code>{code}</code>{/each}</div>
        <div class="row-actions"><button type="button" onclick={() => void copy(recoveryCodes.join('\n'), 'Recovery codes')}>Copy all codes</button><button type="button" onclick={() => recoveryCodes = []}>Clear from screen</button></div>
      {/if}
    </section>
    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Second factor</p><h3>Verify a factor</h3></div><small>{activeMethods.length} active authenticator{activeMethods.length === 1 ? '' : 's'}</small></div>
      <p class="form-note">A successful check consumes a recovery code or the current authenticator time step, exactly like sign-in does.</p>
      <form onsubmit={(event) => { event.preventDefault(); void verifyFactor(); }}>
        <div class="split">
          <label>Factor<select bind:value={mfaKind} disabled={busy}><option value="Totp">Authenticator</option><option value="RecoveryCode">Recovery code</option></select></label>
          {#if mfaKind === 'Totp'}<label>Authenticator method<select bind:value={mfaMethodId} disabled={busy}><option value="">Automatic selection</option>{#each activeMethods as method}<option value={method.methodId}>{method.label ?? method.methodId}</option>{/each}</select></label>{/if}
        </div>
        <label>Code<input type="password" bind:value={mfaCode} autocomplete="off" required disabled={busy} /></label>
        <div class="modal-actions"><button class="primary" disabled={!account || busy || !mfaCode.trim()}>Verify factor</button></div>
      </form>
    </section>
  </div>

{:else if view === 'authentication'}
  <div class="two-column workflow-columns">
    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Sign in</p><h3>Create a user session</h3></div></div>
      <p class="form-note">These are real sign-in operations. Account state, {applicationLabel.toLowerCase()} authority, MFA, and login protection still apply.</p>
      <form onsubmit={(event) => { event.preventDefault(); void authenticate(); }}>
        <label>Authentication<select bind:value={authenticationMode} disabled={busy}><option value="password">Password</option><option value="totp">Primary authenticator / recovery code</option><option value="application">Application-asserted authentication</option></select></label>
        {#if authenticationMode === 'password'}<label>Password<input type="password" bind:value={password} autocomplete="off" required disabled={busy} /></label>{/if}
        {#if authenticationMode === 'totp' && !settings?.enabled}<p class="form-note">Primary authenticator sign-in is currently disabled by server policy.</p>{/if}
        <div class="split">
          <label>{authenticationMode === 'totp' ? 'Primary factor' : 'Second factor'}<select bind:value={mfaKind} disabled={busy}><option value="Totp">Authenticator</option><option value="RecoveryCode">Recovery code</option></select></label>
          <label>Factor code<input type="password" bind:value={mfaCode} autocomplete="off" required={authenticationMode === 'totp'} disabled={busy} /></label>
        </div>
        <label>Authenticator method<select bind:value={mfaMethodId} disabled={busy}><option value="">Automatic selection</option>{#each activeMethods as method}<option value={method.methodId}>{method.label ?? method.methodId}</option>{/each}</select></label>
        <div class="modal-actions"><button class="primary" disabled={!canOperate || authenticationMode === 'totp' && !settings?.enabled}>Create user session</button></div>
      </form>
      {#if session}
        <dl class="secret-details"><div><dt>Session issued</dt><dd><code>{session.sessionId}</code><small>Expires {date(session.expiresAt)}</small></dd></div></dl>
        <div class="row-actions"><button type="button" onclick={() => void copy(session!.token, 'User session token')}>Copy user session token</button></div>
      {/if}
    </section>

    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Inspect</p><h3>Validate or revoke a session</h3></div></div>
      <p class="form-note">Validation checks the selected {applicationLabel.toLowerCase()} and audience and returns session metadata without account claims.</p>
      <label>User session token<textarea bind:value={sessionToken} rows="3" autocomplete="off" disabled={busy}></textarea></label>
      <div class="modal-actions start"><button type="button" class="primary" disabled={busy || !hasApplication || !sessionToken.trim()} onclick={() => void validateSession()}>Validate session</button><button type="button" class="quiet danger-text" disabled={busy || !sessionToken.trim()} onclick={() => void revokeSession()}>Revoke session</button><button type="button" class="quiet" onclick={() => { sessionToken = ''; session = null; sessionValidation = null; }}>Clear</button></div>
      {#if sessionValidation}<div class="notice success"><strong>Valid</strong><span>Session {sessionValidation.sessionId} expires {date(sessionValidation.expiresAt)}.</span></div>{/if}
    </section>

    <section class="panel form-panel">
      <div class="panel-heading"><div><p class="eyebrow">Credential</p><h3>Change password with current proof</h3></div></div>
      <p class="form-note">For a forced administrative replacement use Reset password in the page header. Email recovery lives under Verification.</p>
      <form onsubmit={(event) => { event.preventDefault(); void changePassword(); }}>
        <label>Current password<input type="password" bind:value={currentPassword} autocomplete="off" required disabled={busy} /></label>
        <div class="split"><label>New password<input type="password" bind:value={replacementPassword} autocomplete="new-password" minlength={settings?.minimumPasswordLength ?? 9} maxlength={settings?.maximumPasswordLength ?? 1024} required disabled={busy} /></label><label>Confirm password<input type="password" bind:value={replacementConfirmation} autocomplete="new-password" required disabled={busy} /></label></div>
        <div class="modal-actions"><button class="primary" disabled={!canOperate}>Change password</button></div>
      </form>
    </section>
  </div>

{:else}
  <section class="panel form-panel">
    <div class="panel-heading"><div><p class="eyebrow">Profile</p><h3>Edit profile</h3></div></div>
    <form onsubmit={(event) => { event.preventDefault(); void saveProfile(); }}>
      <label>Display name<input bind:value={profile.displayName} required maxlength="250" disabled={busy} /></label>
      <div class="split">{#each profileFields as field}<label>{field.label}<input bind:value={profile[field.key]} disabled={busy} /></label>{/each}</div>
      <div class="modal-actions"><button class="primary" disabled={busy || !account}>Save profile</button></div>
    </form>
  </section>
{/if}

<style>
  .acting-as { display: flex; align-items: end; gap: 14px; flex-wrap: wrap; margin: 0; }
  .acting-copy { flex: 1 1 220px; align-self: center; }
  .acting-copy strong { display: block; font-size: 13px; }
  .acting-copy small { display: block; margin-top: 1px; color: var(--muted); font-size: 11.5px; }
  .acting-as label { flex: 0 1 260px; margin: 0; }
  .acting-as .header-status { align-self: center; }
  .header-status.unverified span { background: var(--amber); box-shadow: 0 0 0 3px var(--amber-soft); }
  .workflow-columns { align-items: start; }
  .workflow-columns > .panel > form, .form-panel > form { display: grid; gap: 12px; }
  .panel-heading { margin-bottom: 4px; }
  .panel-heading > small { color: var(--muted); font-size: 12px; }
  .modal-actions { margin-top: 4px; }
  .modal-actions.start { justify-content: flex-start; }
  .form-note { margin: 0; }
  .empty-state { padding: 26px 16px; }
  .secret-details { margin-bottom: 0; }
  .secret-details small { display: block; margin-top: 6px; color: var(--faint); font-size: 11.5px; }
  .secret-details textarea { font-family: var(--font-mono); font-size: 11.5px; }
  .proof-code code { font-size: 22px; letter-spacing: .18em; }
  .recovery-grid code { padding: 8px; border-radius: 6px; border: 1px solid var(--line); background: var(--surface-2); text-align: center; }
  .notice .inline { margin-left: auto; padding: 5px 10px; border: 1px solid currentColor; border-radius: 7px; background: rgba(255, 255, 255, .55); font-size: 12px; font-weight: 600; white-space: nowrap; }
  @media (max-width: 1050px) { .workflow-columns { grid-template-columns: 1fr; } }
</style>
