<script lang="ts">
  import { fly } from 'svelte/transition';
  import { dismissSnackbar, snackbar } from '../lib/snackbar';
</script>

{#if $snackbar}
  {#key $snackbar.id}
    <div class="snackbar-region" aria-live="assertive" aria-atomic="true">
      <div class="snackbar" class:success={$snackbar.tone === 'success'} role="alert" in:fly={{ y: -14, duration: 180 }} out:fly={{ y: -8, duration: 120 }}>
        <span class="snackbar-icon" aria-hidden="true">{$snackbar.tone === 'success' ? '✓' : '!'}</span>
        <div class="snackbar-copy"><strong>{$snackbar.title}</strong><span>{$snackbar.message}</span></div>
        <button type="button" aria-label="Dismiss notification" onclick={dismissSnackbar}>×</button>
        <span class="snackbar-timer" aria-hidden="true"></span>
      </div>
    </div>
  {/key}
{/if}
