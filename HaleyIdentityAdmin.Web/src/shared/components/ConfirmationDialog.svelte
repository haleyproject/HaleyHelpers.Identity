<script lang="ts">
  import { confirmation, resolveConfirmation } from '../lib/confirmation';

  function onKeyDown(event: KeyboardEvent) {
    if ($confirmation && event.key === 'Escape') resolveConfirmation(false);
  }
</script>

<svelte:window onkeydown={onKeyDown} />

{#if $confirmation}
  <div
    class="modal-backdrop confirmation-backdrop"
    role="presentation"
    onclick={(event) => event.currentTarget === event.target && resolveConfirmation(false)}
  >
    <div
      class="modal confirmation-dialog"
      class:danger={$confirmation.tone === 'danger'}
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirmation-title"
      aria-describedby="confirmation-message"
    >
      <div class="confirmation-mark" aria-hidden="true">{$confirmation.tone === 'danger' ? '!' : '?'}</div>
      <div class="confirmation-copy">
        <p class="eyebrow">Confirmation required</p>
        <h2 id="confirmation-title">{$confirmation.title}</h2>
        <div id="confirmation-message">
          {#each $confirmation.message.split(/\n\n+/) as paragraph}
            <p>{paragraph}</p>
          {/each}
        </div>
      </div>
      <div class="confirmation-actions">
        <button class="quiet" onclick={() => resolveConfirmation(false)}>
          {$confirmation.cancelLabel ?? 'Cancel'}
        </button>
        <button
          class="primary confirmation-submit"
          class:danger={$confirmation.tone === 'danger'}
          onclick={() => resolveConfirmation(true)}
        >
          {$confirmation.confirmLabel ?? 'Confirm'}
        </button>
      </div>
    </div>
  </div>
{/if}
