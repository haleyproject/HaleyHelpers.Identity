import { writable } from 'svelte/store';

export type SnackbarMessage = {
  id: number;
  title: string;
  message: string;
  tone: 'error' | 'success';
};

export const snackbar = writable<SnackbarMessage | null>(null);

let nextId = 0;
let dismissTimer: ReturnType<typeof setTimeout> | undefined;

export function showError(message: string, title = 'Action failed') {
  const normalized = message.trim();
  if (!normalized) return;

  if (dismissTimer) clearTimeout(dismissTimer);
  snackbar.set({ id: ++nextId, title, message: normalized, tone: 'error' });
  dismissTimer = setTimeout(dismissSnackbar, 4000);
}

export function showSuccess(message: string, title = 'Saved') {
  const normalized = message.trim();
  if (!normalized) return;
  if (dismissTimer) clearTimeout(dismissTimer);
  snackbar.set({ id: ++nextId, title, message: normalized, tone: 'success' });
  dismissTimer = setTimeout(dismissSnackbar, 4000);
}

export function dismissSnackbar() {
  if (dismissTimer) clearTimeout(dismissTimer);
  dismissTimer = undefined;
  snackbar.set(null);
}
