<script lang="ts">
  import { adminApi, ApiError } from '../lib/api';
  import { showError } from '../lib/snackbar';
  import haleyLogo from '../assets/haley.svg';
  export let logo = haleyLogo;
  export let brand = 'Haley Identity';
  export let passwordSetting = 'Haley:Identity:Management:PasswordHash';

  export let passwordConfigured: boolean;
  export let onAuthenticated: () => void;

  let password = '';
  let busy = false;
  let error = '';

  $: if (error) { showError(error, 'Sign-in failed'); error = ''; }

  async function submit() {
    if (!password) return;
    busy = true;
    error = '';
    try {
      await adminApi.login(password);
      password = '';
      await adminApi.session();
      onAuthenticated();
    } catch (reason) {
      error = reason instanceof ApiError ? reason.message : 'The local admin service could not be reached.';
    } finally {
      busy = false;
    }
  }
</script>

<main class="login-stage">
  <div class="ambient ambient-one"></div>
  <div class="ambient ambient-two"></div>
  <section class="login-card">
    <div class="brand-mark"><img src={logo} alt={brand} /></div>
    <h1>Auth Intelligence</h1>
    <p class="lede">Local administration for identity, access, and platform trust.</p>

    {#if passwordConfigured}
      <form onsubmit={(event) => { event.preventDefault(); void submit(); }}>
        <label for="admin-password">Superadmin passphrase</label>
        <input
          id="admin-password"
          type="password"
          bind:value={password}
          autocomplete="current-password"
          placeholder="Enter your local passphrase"
        />
        <button class="primary full" type="submit" disabled={busy || !password}>
          {busy ? 'Verifying…' : 'Enter Auth Intelligence'}
        </button>
      </form>
    {:else}
      <div class="setup-callout" role="status">
        <strong>One-time setup required</strong>
        <p>Generate a management password hash with the credential tool, then set <code>{passwordSetting}</code> in the host configuration.</p>
        <code class="command">Kida.Service.Host.exe hash-admin-password</code>
      </div>
    {/if}

    <div class="local-proof"><span></span> Protected management boundary</div>
  </section>
</main>
