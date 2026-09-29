// Numeric wire values mirror the capability-owned C# status enums.
// Persisted lifecycle values contain one allowed bit. Labels belong to presentation.
export enum RecordStatus {
  Pending = 1,
  Active = 2,
  Retired = 4,
  Locked = 8,
  Suspended = 16,
  Inactive = 32,
  Revoked = 64,
  Expired = 128,
  Deprecated = 256,
  Ended = 512,
  Verified = 1024,
  Consumed = 2048,
  Cancelled = 4096,
  Exhausted = 8192,
  Staged = 16384,
  Retiring = 32768,
  Planned = 65536,
  Provisioning = 131072,
  Invited = 262144,
  Left = 524288,
  Accepted = 1048576,
  Trial = 2097152,
  PastDue = 4194304,
  Released = 8388608,
  Disabled = 16777216,
  Uninstalled = 33554432,
}

export enum OperationalStatus {
  Pending = 1,
  Active = 2,
  Retired = 4,
  Locked = 8,
  Suspended = 16,
  Inactive = 32,
  Revoked = 64,
  Expired = 128,
  Deprecated = 256,
  Ended = 512,
  Verified = 1024,
  Consumed = 2048,
  Cancelled = 4096,
  Exhausted = 8192,
  Staged = 16384,
  Retiring = 32768,
  Released = 8388608,
  Recorded = 65536,
  Linked = 131072,
  Leased = 262144,
  Processed = 524288,
  Failed = 1048576,
  Succeeded = 2097152,
  Blocked = 4194304,
  PasswordChangeRequired = 16777216,
  MfaRequired = 33554432,
  Unknown = 67108864,
}

export enum CertificateStatus { NotYetValid = 1, Valid = 2, Expired = 4, Invalid = 8 }
export enum AppHealthStatus { Unknown = 1, Healthy = 2, Degraded = 4, Unhealthy = 8, Offline = 16 }

const words = (name: string) => name.replace(/([a-z])([A-Z])/g, '$1 $2');
export function statusLabel(value: number | ''): string {
  return value === '' ? 'All statuses' : words(RecordStatus[value] ?? `Unknown (${value})`);
}
export function statusClass(value: number): string {
  return (RecordStatus[value] ?? 'unknown').replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
}
export function operationalStatusLabel(value: number | ''): string {
  return value === '' ? 'All statuses' : words(OperationalStatus[value] ?? `Unknown (${value})`);
}
export function operationalStatusClass(value: number): string {
  return (OperationalStatus[value] ?? 'unknown').replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
}
export function certificateStatusLabel(value: number): string {
  return words(CertificateStatus[value] ?? `Unknown (${value})`);
}
export function certificateStatusClass(value: number): string {
  return (CertificateStatus[value] ?? 'invalid').replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
}
