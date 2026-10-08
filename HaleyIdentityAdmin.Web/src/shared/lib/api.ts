import type { AdminSession, AdminTotpEnrollment, BulkPasswordResetResponse, BulkUserImportResponse, BulkUserImportRowResult, IdentityClientPolicy, IdentityOperationalArea, IdentityOperationalPage, IdentityOperationalRecord, IdentityProvider, IdentityStatus, LoginProtectionPolicy, MfaDomainRule, MfaMethod, OAuthClient, OAuthClientPage, OAuthClientType, SamlCertificate, Section, TotpEnrollmentCompletion, UserActivityFilter, UserIdentity, UserIdentityPage, UserLoginAttempt, UserLoginAttemptPage, UserMfaPolicyOverride, UserProfile, UserSession, UserSessionPage, UserSortOrder } from './types';
import { RecordStatus } from './statuses';
import type { RegisteredIdentityApplication, IdentityApplicationCredential } from './types';


export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly traceId?: string
  ) {
    super(message);
  }
}

interface AdminRuntimeConfig {
  title?: string;
  basePath?: string;
  apiBasePath?: string;
}

export function joinPath(base: string, path: string): string {
  return `${base.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}

function normalizeBasePath(value: string): string {
  const path = value.trim();
  if (!path || path === '/') return '/';
  return `/${path.replace(/^\/+|\/+$/g, '')}/`;
}

function documentBasePath(): string {
  return normalizeBasePath(new URL('.', window.location.href).pathname);
}

function ensureSameOriginPath(name: string, value: string): string {
  const path = value.trim();
  if (
    !path ||
    path.startsWith('//') ||
    path.includes('\\') ||
    path.includes('?') ||
    path.includes('#') ||
    /^[a-z][a-z0-9+.-]*:/i.test(path)
  ) {
    throw new Error(`${name} must be a same-origin path without a query or fragment.`);
  }
  return path;
}

export class IdentityAdminApi {
  title = 'Identity Administration';
  readonly extended: boolean;
  private readonly configFile: string;
  private readonly defaultTitle: string;
  constructor(extended = false) { this.extended = extended; this.configFile = extended ? 'kida-admin.config.json' : 'identity-admin.config.json'; this.defaultTitle = extended ? 'Auth Intelligence Overview' : 'Identity Administration'; this.title = this.defaultTitle; this.apiRoot = joinPath(this.basePath, extended ? "admin/api" : "api"); }
  private csrf = '';
  private basePath = documentBasePath();
  protected apiRoot = joinPath(this.basePath, 'api');

  async configure(): Promise<void> {
    this.title = this.defaultTitle;
    const configUrl = new URL('./' + this.configFile, window.location.href).toString();
    try {
      const response = await fetch(configUrl, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' }
      });
      if (!response.ok) return;

      const config = await response.json() as AdminRuntimeConfig;
      if (typeof config.title === 'string' && config.title.trim()) {
        this.title = config.title.trim();
      }
      const configuredBasePath = config.basePath === undefined
        ? this.basePath
        : normalizeBasePath(ensureSameOriginPath('basePath', config.basePath));
      const configuredApiPath = config.apiBasePath === undefined
        ? (this.extended ? 'admin/api' : 'api')
        : ensureSameOriginPath('apiBasePath', config.apiBasePath);

      this.basePath = configuredBasePath;
      this.apiRoot = configuredApiPath.startsWith('/')
        ? `/${configuredApiPath.replace(/^\/+|\/+$/g, '')}`
        : joinPath(configuredBasePath, configuredApiPath);
    } catch {
      // The document directory remains a safe same-origin fallback.
    }
  }

  async session(): Promise<AdminSession> {
    const session = await this.request<AdminSession>('session');
    this.csrf = session.antiforgeryToken;
    return session;
  }

  identityApplications(): Promise<RegisteredIdentityApplication[]> {
    return this.request('applications');
  }

  registerIdentityApplication(displayName: string, applicationId?: string): Promise<IdentityApplicationCredential> {
    return this.request('applications', { method: 'POST', body: { displayName, applicationId } });
  }

  rotateIdentityApplicationKey(applicationId: string): Promise<IdentityApplicationCredential> {
    return this.request(`applications/${applicationId}/keys`, { method: 'POST' });
  }

  revokeIdentityApplicationKey(applicationId: string, keyId: string): Promise<void> {
    return this.request(`applications/${applicationId}/keys/${encodeURIComponent(keyId)}`, { method: 'DELETE' });
  }

  revokeIdentityApplication(applicationId: string): Promise<void> {
    return this.request(`applications/${applicationId}`, { method: 'DELETE' });
  }

  login(password: string): Promise<{ authenticated: boolean }> {
    return this.request('login', { method: 'POST', body: { password } });
  }

  logout(): Promise<void> {
    return this.request('logout', { method: 'POST' });
  }

  users(
    query = '',
    status: number | '' = '',
    activity: UserActivityFilter = 'All',
    sort: UserSortOrder = 'CreatedNewest',
    page = 1,
    pageSize = 20
  ): Promise<UserIdentityPage> {
    const params = new URLSearchParams();
    if (query) params.set('query', query);
    if (status) params.set('status', String(status));
    params.set('activity', activity);
    params.set('sort', sort);
    params.set('page', String(page));
    params.set('pageSize', String(pageSize));
    return this.request(`users?${params}`);
  }

  createUser(input: { username: string; displayName: string; password: string; activateImmediately: boolean; requirePasswordChange: boolean }): Promise<UserIdentity> {
    return this.request('users', { method: 'POST', body: input });
  }

  importUsers(
    file: File,
    input: { initialPassword: string; activateImmediately: boolean; requirePasswordChange: boolean }
  ): Promise<BulkUserImportResponse> {
    const form = new FormData();
    form.set('file', file);
    form.set('initialPassword', input.initialPassword);
    form.set('activateImmediately', String(input.activateImmediately));
    form.set('requirePasswordChange', String(input.requirePasswordChange));
    return this.request('users/import/csv', { method: 'POST', form });
  }

  resetPasswords(input: {
    userIds: string[];
    newPassword: string;
    requirePasswordChange: boolean;
    reasonCode: string;
  }): Promise<BulkPasswordResetResponse> {
    return this.request('users/password/reset-bulk', { method: 'POST', body: input });
  }

  changeUserStatus(userId: string, status: number, reasonCode: string): Promise<void> {
    return this.request(`users/${userId}/status`, { method: 'PUT', body: { status, reasonCode } });
  }

  restoreUser(userId: string, reasonCode = 'administrator_restored'): Promise<void> {
    return this.request(`users/${userId}/restore`, { method: 'POST', body: { reasonCode } });
  }

  permanentlyDeleteUser(userId: string, reasonCode = 'administrator_deleted'): Promise<void> {
    return this.request(`users/${userId}/permanent`, {
      method: 'DELETE',
      body: { confirmation: userId, reasonCode }
    });
  }

  userSessions(userId: string, view: RecordStatus.Active | 'all' = RecordStatus.Active, page = 1): Promise<UserSessionPage> {
    const params = new URLSearchParams({ view: view === RecordStatus.Active ? 'active' : view, page: String(page) });
    return this.request(`users/${userId}/sessions?${params}`);
  }

  revokeSession(sessionId: string): Promise<void> {
    return this.request(`sessions/${sessionId}`, { method: 'DELETE' });
  }

  userProfile(userId: string): Promise<UserProfile> {
    return this.request(`users/${userId}/profile`);
  }

  updateUserDisplayName(userId: string, displayName: string): Promise<UserProfile> {
    return this.request(`users/${userId}/profile/display-name`, {
      method: 'PUT', body: { displayName }
    });
  }

  userMfa(userId: string): Promise<MfaMethod[]> {
    return this.request(`users/${userId}/mfa`);
  }

  userLoginAttempts(userId: string, page = 1, pageSize = 10): Promise<UserLoginAttemptPage> {
    const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
    return this.request(`users/${userId}/login-attempts?${params}`);
  }

  loginProtectionPolicy(): Promise<LoginProtectionPolicy> {
    return this.request('identity/login-protection');
  }

  releaseUserLoginProtection(userId: string): Promise<void> {
    return this.request(`users/${userId}/login-protection/release`, { method: 'POST' });
  }

  beginUserTotpEnrollment(userId: string, accountLabel: string, replaceMethodId: string | null): Promise<AdminTotpEnrollment> {
    return this.request(`users/${userId}/mfa/totp`, {
      method: 'POST', body: { accountLabel, replaceMethodId }
    });
  }

  confirmUserTotpEnrollment(userId: string, ticket: string, code: string): Promise<TotpEnrollmentCompletion> {
    return this.request(`users/${userId}/mfa/totp/confirm`, {
      method: 'POST', body: { ticket, code }
    });
  }

  testUserTotp(userId: string, methodId: string, code: string): Promise<void> {
    return this.request(`users/${userId}/mfa/${methodId}/test`, {
      method: 'POST', body: { code }
    });
  }

  retireUserMfaMethod(userId: string, methodId: string): Promise<void> {
    return this.request(`users/${userId}/mfa/${methodId}`, { method: 'DELETE' });
  }

  userMfaPolicyOverrides(userId: string): Promise<UserMfaPolicyOverride[]> {
    return this.request(`users/${userId}/mfa/policies`);
  }

  setUserMfaPolicyOverride(
    userId: string,
    clientId: string,
    resource: string,
    requirement: 'none' | 'required'
  ): Promise<void> {
    return this.request(
      `users/${userId}/mfa/policies/${clientId}/${encodeURIComponent(resource)}`,
      { method: 'PUT', body: { requirement } }
    );
  }

  deleteUserMfaPolicyOverride(userId: string, clientId: string, resource: string): Promise<void> {
    return this.request(
      `users/${userId}/mfa/policies/${clientId}/${encodeURIComponent(resource)}`,
      { method: 'DELETE' }
    );
  }

  overrideEmailVerification(userId: string, contactId: string, reasonCode = 'administrator_attested'): Promise<void> {
    return this.request(`users/${userId}/contacts/${contactId}/verification/override`, {
      method: 'POST', body: { reasonCode }
    });
  }

  recordLoginEmailContact(userId: string): Promise<void> {
    return this.request(`users/${userId}/contacts/email/from-login`, { method: 'POST' });
  }

  clients(page = 1): Promise<OAuthClientPage> {
    return this.request(`clients?page=${page}`);
  }

  async identityProviders(): Promise<IdentityProvider[]> {
    const providers = await this.request<IdentityProvider[]>('identity/providers');
    if (!this.extended) return providers;
    const bindings = await this.request<Array<{providerId: string; tenantId: string | null}>>('identity/provider-tenants');
    return providers.map(provider => ({ ...provider, tenantId: bindings.find(binding => binding.providerId === provider.providerId)?.tenantId ?? null }));
  }

  samlCertificates(): Promise<SamlCertificate[]> {
    return this.request('identity/saml-certificates');
  }

  async uploadSamlCertificate(
    file: File,
    name: string,
    replace = false,
    confirmation = ''
  ): Promise<SamlCertificate> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return this.request('identity/saml-certificates', {
      method: 'POST',
      body: { name, content: btoa(binary), replace, confirmation }
    });
  }

  async saveIdentityProvider(providerId: string | null, input: {
    code: string;
    protocol: 'Saml' | 'SignedCallback';
    issuer: string;
    displayName: string;
    configuration: string;
    authoritativeDomains: string[];
    discoveryDomains: string[];
    tenantId: string | null;
    status: number;
    signingCertificates: string[];
  }): Promise<IdentityProvider> {
    const path = providerId
      ? `identity/providers/${providerId}`
      : 'identity/providers';
    const provider = await this.request<IdentityProvider>(path, { method: providerId ? 'PUT' : 'POST', body: input });
    if (this.extended) await this.request(`identity/providers/${provider.providerId}/tenant`, { method: 'PUT', body: { providerId: provider.providerId, tenantId: input.tenantId } });
    return provider;
  }

  identityClientPolicies(): Promise<IdentityClientPolicy[]> {
    return this.request('identity/client-policies');
  }

  saveIdentityClientPolicy(clientId: string, resource: string, input: {
    emailVerification: 'Disabled' | 'Immediate' | 'Grace';
    graceSeconds: number;
    allowLegacyUserCreate: boolean;
    mfaRequirement: 'none' | 'optional' | 'required';
    mfaDomainRules: Array<{ ruleId: string; domain: string; requirement: 'none' | 'optional' | 'required'; includeSubdomains: boolean; priority: number }>;
  }): Promise<void> {
    return this.request(`identity/clients/${clientId}/policies/${encodeURIComponent(resource)}`, {
      method: 'PUT', body: input
    });
  }

  identityOperations(
    area: IdentityOperationalArea,
    query = '',
    status: number | '' = '',
    page = 1,
    pageSize = 20
  ): Promise<IdentityOperationalPage> {
    const params = new URLSearchParams({ area, page: String(page), pageSize: String(pageSize) });
    if (query) params.set('query', query);
    if (status) params.set('status', String(status));
    return this.request(`identity/operations?${params}`);
  }

  protected async request<T>(path: string, options: { method?: string; body?: unknown; form?: FormData } = {}): Promise<T> {
    const method = options.method ?? 'GET';
    const headers = new Headers({ Accept: 'application/json' });
    if (options.body !== undefined) headers.set('Content-Type', 'application/json');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) headers.set(this.extended ? 'X-KIDA-CSRF' : 'X-CSRF-TOKEN', this.csrf);

    const response = await fetch(joinPath(this.apiRoot, path), {
      method,
      credentials: 'same-origin',
      headers,
      body: options.form ?? (options.body === undefined ? undefined : JSON.stringify(options.body))
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({})) as { title?: string; detail?: string; code?: string; traceId?: string };
      throw new ApiError(problem.detail?.trim() || problem.title?.trim() || `Request failed with status ${response.status}.`, response.status, problem.code, problem.traceId);
    }

    if (response.status === 204) return undefined as T;
    return await response.json() as T;
  }
}

export let adminApi = new IdentityAdminApi();
export function setAdminApi(value: IdentityAdminApi): void { adminApi = value; }

export function uuid7(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let milliseconds = BigInt(Date.now());
  for (let index = 5; index >= 0; index--) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
