<script lang="ts">
  import { onMount } from 'svelte';
  import Navigation from './shared/components/Navigation.svelte';
  import Login from './shared/components/Login.svelte';
  import Users from './shared/features/Users.svelte';
  import Federation from './shared/features/Federation.svelte';
  import Applications from './features/Applications.svelte';
  import ConfirmationDialog from './shared/components/ConfirmationDialog.svelte';
  import Snackbar from './shared/components/Snackbar.svelte';
  import { adminApi } from './shared/lib/api';
  import type { AdminSession, Section } from './shared/lib/types';
  import logo from './shared/assets/haley.svg';

  let session: AdminSession | null = null;
  let active: Section = 'users';
  let collapsed = false;
  let error = '';
  let loading = true;
  onMount(() => { void bootstrap(); });

  async function bootstrap() {
    loading = true; error = '';
    try { await adminApi.configure(); session = await adminApi.session(); document.title = adminApi.title; }
    catch (reason) { error = reason instanceof Error ? reason.message : 'Identity host is unavailable.'; }
    finally { loading = false; }
  }
  async function authenticated() { session = await adminApi.session(); }
  async function logout() { await adminApi.logout(); session = await adminApi.session(); active = 'users'; }
</script>

{#if loading}
  <div class="boot-screen"><div class="brand-mark"><img src={logo} alt="Haley" /></div><p>Loading identity administration…</p></div>
{:else if error}
  <main class="login-stage"><section class="login-card"><h1>Connection unavailable</h1><p>{error}</p><button class="primary full" onclick={() => void bootstrap()}>Retry</button></section></main>
{:else if !session?.authenticated}
  <Login passwordConfigured={session?.passwordConfigured ?? false} onAuthenticated={() => void authenticated()} />
{:else}
  <div class="app-shell" class:nav-collapsed={collapsed}>
    <Navigation {active} capabilities={['identity']} {collapsed}
      items={[{ id: 'users', label: 'Identity', icon: '◎' }, { id: 'identity-applications', label: 'Applications', icon: '▦' }, { id: 'federation', label: 'Federation', icon: '↗' }]}
      onToggle={() => collapsed = !collapsed} onSelect={(value) => active = value} onLogout={() => void logout()} />
    <main class="content">{#if active === 'federation'}<Federation />{:else if active === 'identity-applications'}<Applications />{:else}<Users />{/if}</main>
  </div>
{/if}
<ConfirmationDialog />
<Snackbar />
