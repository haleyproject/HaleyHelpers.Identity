import { RecordStatus } from './statuses';

export type IdentityStatus = RecordStatus.Pending | RecordStatus.Active | RecordStatus.Locked | RecordStatus.Suspended | RecordStatus.Retired;
export type UserActivityFilter = 'All' | 'NeverLoggedIn' | 'HasLoggedIn' | 'PasswordChangeRequired';
export type UserSortOrder = 'CreatedNewest' | 'CreatedOldest' | 'LastLoginNewest' | 'LastLoginOldest';
export type Section = 'overview' | 'operations' | 'users' | 'clients' | 'audiences' | 'federation' | 'scopes' | 'tenants' | 'access' | 'entitlements' | 'apps' | 'info';
export type OAuthClientType = 'Public' | 'Confidential' | 'Service';

export interface AdminSession {
  authenticated: boolean;
  passwordConfigured: boolean;
  antiforgeryToken: string;
}

export interface UserIdentity {
  userId: string;
  displayName: string;
  status: IdentityStatus;
  username: string | null;
  createdAt: string;
  lastAuthenticatedAt: string | null;
  passwordChangeRequired: boolean;
}

export interface UserIdentityPage {
  users: UserIdentity[];
  page: number;
  pageSize: number;
  hasNext: boolean;
}

export interface UserProfile {
  userId: string;
  displayName: string;
  givenName: string | null;
  familyName: string | null;
  preferredName: string | null;
  locale: string | null;
  timeZone: string | null;
  avatarUri: string | null;
  modifiedAt: string;
}

export interface MfaMethod {
  methodId: string;
  userId: string;
  kind: 'EmailOtp' | 'Saml' | 'Totp' | 'RecoveryCode';
  label: string | null;
  status: number;
  createdAt: string;
  verifiedAt: string | null;
  lastUsedAt: string | null;
}

export interface AdminTotpEnrollment {
  methodId: string;
  ticket: string;
  qrCodeSvg: string;
  expiresAt: string;
  attemptsRemaining: number;
  replacesExistingMethod: boolean;
}

export interface TotpEnrollmentCompletion {
  methodId: string;
  recoveryCodes: string[];
  returnUri: string | null;
}

export interface UserLoginAttempt {
  attemptId: number;
  userId: string;
  clientId: string | null;
  outcome: string;
  reasonCode: string | null;
  occurredAt: string;
}

export interface UserLoginAttemptPage {
  attempts: UserLoginAttempt[];
  page: number;
  pageSize: number;
  hasNext: boolean;
}

export interface LoginProtectionPolicy {
  maxFailedAttempts: number;
  lockoutSeconds: number;
}

export interface BulkUserImportRowResult {
  rowNumber: number;
  employeeId: string | null;
  username: string;
  displayName: string;
  succeeded: boolean;
  userId: string | null;
  errorCode: string | null;
}

export interface BulkUserImportResponse {
  totalRows: number;
  created: number;
  failed: number;
  rows: BulkUserImportRowResult[];
}

export interface BulkPasswordResetResponse {
  totalUsers: number;
  reset: number;
  failed: number;
  users: Array<{ userId: string; succeeded: boolean; errorCode: string | null }>;
}

export interface UserSession {
  sessionId: string;
  userId: string;
  clientId: string | null;
  applicationId?: string | null;
  resource: string | null;
  status: number;
  authenticatedAt: string;
  lastSeenAt: string;
  expiresAt: string;
  endedAt: string | null;
}

export type IdentityOperationalArea =
  | 'Contacts'
  | 'Credentials'
  | 'Origins'
  | 'Federation'
  | 'Mfa'
  | 'VerificationChallenges'
  | 'VerificationGrants'
  | 'FederationAttempts'
  | 'Sessions'
  | 'RefreshFamilies'
  | 'LoginAttempts'
  | 'AccountLocks'
  | 'ClientSecrets'
  | 'TokenRevocations'
  | 'Outbox';

export interface IdentityOperationalRecord {
  recordKey: string;
  area: IdentityOperationalArea;
  type: string;
  status: number;
  recordId: string | null;
  userId: string | null;
  userDisplayName: string | null;
  userEmail: string | null;
  clientId: string | null;
  clientIdentifier: string | null;
  clientDisplayName: string | null;
  tenantId: string | null;
  provider: string | null;
  audience: string | null;
  detail: string | null;
  attempts: number | null;
  generation: number | null;
  occurredAt: string;
  expiresAt: string | null;
  completedAt: string | null;
}

export interface IdentityOperationalPage {
  records: IdentityOperationalRecord[];
  area: IdentityOperationalArea;
  page: number;
  pageSize: number;
  hasNext: boolean;
}

export interface UserSessionPage {
  sessions: UserSession[];
  page: number;
  pageSize: number;
  hasNext: boolean;
}

export interface OAuthClient {
  clientId: string;
  servicePrincipalId: string | null;
  clientIdentifier: string;
  displayName: string;
  clientType: OAuthClientType;
  grantTypes: string[];
  allowedScopes: string[];
  accessTokenSeconds: number;
  status: number;
  createdAt: string;
  modifiedAt: string;
  ownerTenantId: string | null;
  connectedAppId: string | null;
  resourceGrants: Array<{ audience: string; allowedScopes: string[] }> | null;
  redirectUris: string[] | null;
  managedAudience: string | null;
  hostedAudiences: string[] | null;
}

export interface OAuthClientPage {
  clients: OAuthClient[];
  page: number;
  pageSize: number;
  hasNext: boolean;
}

export interface IdentityProvider {
  providerId: string;
  code: string;
  protocol: 'Saml' | 'SignedCallback';
  issuer: string;
  displayName: string;
  status: number;
  tenantId: string | null;
  configuration: string;
  authoritativeDomains: string[];
  discoveryDomains?: string[];
  modifiedAt: string;
  signingCertificates: string[] | null;
}

export interface SamlCertificate {
  name: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  sha256Fingerprint: string;
  size: number;
  status: number;
  modifiedAt: string;
  referencingProviders: string[];
}

export interface IdentityClientPolicy {
  clientId: string;
  resource: string;
  emailVerification: 'Disabled' | 'Immediate' | 'Grace';
  graceSeconds: number;
  allowLegacyUserCreate: boolean;
  mfaRequirement: 'none' | 'optional' | 'required';
  modifiedAt: string;
  mfaDomainRules: MfaDomainRule[];
}

export interface MfaDomainRule {
  ruleId: string;
  domain: string;
  requirement: 'none' | 'optional' | 'required';
  includeSubdomains: boolean;
  priority: number;
}

export interface UserMfaPolicyOverride {
  userId: string;
  clientId: string;
  resource: string;
  requirement: 'none' | 'required';
  modifiedAt: string;
}

