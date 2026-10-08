<script lang="ts">
  import { onMount } from 'svelte';
  import { adminApi } from '../shared/lib/api';
  import { copyText } from '../shared/lib/clipboard';
  import { requestConfirmation } from '../shared/lib/confirmation';
  import { showError } from '../shared/lib/snackbar';
  import { RecordStatus } from '../shared/lib/statuses';
  import type { IdentityApplicationCredential, RegisteredIdentityApplication } from '../shared/lib/types';

  let applications: RegisteredIdentityApplication[] = [];
  let displayName = '';
  let applicationId = '';
  let saving = false;
  let loading = true;
  let issued: IdentityApplicationCredential | null = null;
  let copied = false;
  let notice = '';
  $: configuration = issued ? JSON.stringify({ Haley: { Identity: {
    ApplicationId: issued.applicationId, SessionKeyId: issued.sessionKeyId, SessionBindingSecret: issued.sessionBindingSecret
  } } }, null, 2) : '';

  onMount(() => { void load(); });

  async function load() {
    loading = true;
    try { applications = await adminApi.identityApplications(); }
    catch (reason) { failure(reason); }
    finally { loading = false; }
  }

  async function register(event: SubmitEvent) {
    event.preventDefault();
    saving = true; notice = ''; copied = false;
    try {
      issued = await adminApi.registerIdentityApplication(displayName.trim(), applicationId.trim() || undefined);
      displayName = ''; applicationId = '';
      await load();
    } catch (reason) { failure(reason); }
    finally { saving = false; }
  }

  async function rotate(app: RegisteredIdentityApplication) {
    if (!await requestConfirmation({ title: `Rotate ${app.displayName}'s key?`,
      message: 'A new key will be issued. Existing keys stay valid while you update the application. Revoke the old keys after switching.', confirmLabel: 'Issue new key' })) return;
    saving = true; notice = ''; copied = false;
    try { issued = await adminApi.rotateIdentityApplicationKey(app.applicationId); await load(); }
    catch (reason) { failure(reason); }
    finally { saving = false; }
  }

  async function revokeKey(app: RegisteredIdentityApplication, keyId: string) {
    if (!await requestConfirmation({ title: 'Revoke application key?',
      message: `Requests using ${keyId} for ${app.displayName} will be rejected. Confirm that callers have switched to another key.`, confirmLabel: 'Revoke key', tone: 'danger' })) return;
    saving = true;
    try {
      await adminApi.revokeIdentityApplicationKey(app.applicationId, keyId);
      if (issued?.sessionKeyId === keyId) issued = null;
      notice = 'Key revoked.'; await load();
    } catch (reason) { failure(reason); }
    finally { saving = false; }
  }

  async function revoke(app: RegisteredIdentityApplication) {
    if (!await requestConfirmation({ title: `Revoke ${app.displayName}?`,
      message: 'All application keys will stop working. This application will no longer be able to call Identity. User accounts and stored sessions are retained.',
      confirmLabel: 'Revoke application', tone: 'danger' })) return;
    saving = true;
    try {
      await adminApi.revokeIdentityApplication(app.applicationId);
      if (issued?.applicationId === app.applicationId) issued = null;
      notice = 'Application revoked.'; await load();
    } catch (reason) { failure(reason); }
    finally { saving = false; }
  }

  async function copyConfiguration() {
    copied = await copyText(configuration);
    if (!copied) showError('Select and copy the configuration manually.', 'Clipboard unavailable');
  }

  function failure(reason: unknown) {
    showError(reason instanceof Error ? reason.message : 'The application operation failed.', 'Applications');
  }
</script>

<section class="applications-page">
  <header class="page-header">
    <div><p class="eyebrow">Identity access</p><h1>Applications</h1><p>Register the backends allowed to call this identity service.</p></div>
    <button class="quiet" disabled={loading || saving} onclick={() => void load()}>Refresh</button>
  </header>

  <form class="panel compact registration" onsubmit={(event) => void register(event)}>
    <label>Application name<input bind:value={displayName} maxlength="120" required placeholder="LearnDesk" autocomplete="off" /></label>
    <label>Application ID <small>(optional)</small><input bind:value={applicationId} placeholder="Generated if left blank" autocomplete="off" /></label>
    <button class="primary" disabled={saving || issued !== null}>Register application</button>
  </form>

  {#if issued}
    <section class="panel compact credential-panel" aria-label="New application credential">
      <h2>Save the new credential</h2>
      <p>This secret is shown only when issued. Save it in the calling backend's private settings. It cannot be retrieved from this page later.</p>
      <textarea aria-label="Application configuration" readonly rows="10" value={configuration}></textarea>
      <div class="credential-actions"><button class="primary" onclick={() => void copyConfiguration()}>{copied ? 'Copied' : 'Copy configuration'}</button>
        <button class="quiet" onclick={() => { issued = null; copied = false; }}>I have saved it</button></div>
    </section>
  {/if}
  {#if notice}<p role="status">{notice}</p>{/if}

  <section class="panel table-panel">
    <div class="panel-heading"><h2>Registered applications</h2><small>{applications.length} total</small></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Application</th><th>Status</th><th>Keys</th><th>Actions</th></tr></thead>
      <tbody>
        {#each applications as app (app.applicationId)}
          <tr>
            <td><strong>{app.displayName}</strong><code class="application-id">{app.applicationId}</code></td>
            <td>{app.status === RecordStatus.Active ? 'Active' : 'Revoked'}</td>
            <td>
              {#each app.keyIds as keyId}
                <div class="key-row"><code>{keyId}</code>{#if issued?.sessionKeyId === keyId}<small>New</small>{/if}
                  <button class="quiet danger-text" disabled={saving || app.keyIds.length < 2} title={app.keyIds.length < 2 ? 'Rotate first or revoke the application to remove its final key.' : 'Revoke this key'} onclick={() => void revokeKey(app, keyId)}>Revoke key</button></div>
              {:else}<span>No active keys</span>{/each}
            </td>
            <td>{#if app.status === RecordStatus.Active}<div class="application-actions">
              <button class="quiet" disabled={saving || issued !== null} onclick={() => void rotate(app)}>Rotate key</button>
              <button class="quiet danger-text" disabled={saving} onclick={() => void revoke(app)}>Revoke application</button>
            </div>{/if}</td>
          </tr>
        {:else}<tr><td colspan="4">{loading ? 'Loading applications…' : 'No applications registered yet.'}</td></tr>{/each}
      </tbody>
    </table></div>
  </section>
</section>

<style>
  .applications-page { display: grid; gap: 1.25rem; }
  .registration { display: flex; align-items: end; flex-wrap: wrap; gap: 1rem; }
  .registration label { display: grid; gap: .5rem; flex: 1 1 16rem; }
  .credential-panel textarea { width: 100%; resize: vertical; font-family: monospace; }
  .credential-actions, .application-actions, .key-row { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
  .credential-actions { margin-top: .75rem; }
  .key-row + .key-row { margin-top: .5rem; }
  .application-id { display: block; margin-top: .4rem; overflow-wrap: anywhere; }
  .key-row code { overflow-wrap: anywhere; }
</style>
