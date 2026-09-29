import { writable } from 'svelte/store';

export type ConfirmationTone = 'default' | 'danger';

export type ConfirmationRequest = {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: ConfirmationTone;
};

export const confirmation = writable<ConfirmationRequest | null>(null);

let activeResolution: ((confirmed: boolean) => void) | null = null;

export function requestConfirmation(request: ConfirmationRequest): Promise<boolean> {
  activeResolution?.(false);

  return new Promise<boolean>((resolve) => {
    activeResolution = resolve;
    confirmation.set(request);
  });
}

export function resolveConfirmation(confirmed: boolean): void {
  const resolve = activeResolution;
  activeResolution = null;
  confirmation.set(null);
  resolve?.(confirmed);
}
