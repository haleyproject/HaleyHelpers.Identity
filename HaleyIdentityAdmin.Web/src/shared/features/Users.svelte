<script lang="ts">
  import { RecordStatus, OperationalStatus, statusLabel, statusClass, operationalStatusLabel } from '../lib/statuses';
  import { onMount } from 'svelte';
  import { adminApi, ApiError } from '../lib/api';
  import { requestConfirmation } from '../lib/confirmation';
  import { copyText } from '../lib/clipboard';
  import { showError } from '../lib/snackbar';
  import type {
    BulkPasswordResetResponse,
    BulkUserImportResponse,
    IdentityOperationalRecord,
    IdentityClientPolicy,
    IdentityStatus,
    MfaMethod,
    AdminTotpEnrollment,
    TotpEnrollmentCompletion,
    UserActivityFilter,
    UserIdentity,
    UserSortOrder,
    UserProfile,
    UserSession,
    UserSessionPage,
    UserLoginAttemptPage,
    LoginProtectionPolicy,
    UserMfaPolicyOverride
  } from '../lib/types';

  export let onAccess: (subjectId: string) => void = () => {};

  type SessionView = RecordStatus.Active | 'all';
  type ControlSection = 'profile' | 'mfa' | 'attempts' | 'lifecycle';
  type LifecycleSection = 'identity' | 'verification' | 'evidence';

  let users: UserIdentity[] = [];
  let query = '';
  let statusFilter: number | '' = '';
  let activityFilter: UserActivityFilter = 'All';
  let sortOrder: UserSortOrder = 'CreatedNewest';
  let page = 1;
  let pageSize = 20;
  let hasNext = false;
  let loading = true;
  let error = '';
  let notice = '';
  let showCreate = false;
  let showImport = false;
  let showReset = false;
  let inspectedUser: UserIdentity | null = null;
  let controlSection: ControlSection = 'profile';
  let lifecycleSection: LifecycleSection = 'identity';
  let inspectedProfile: UserProfile | null = null;
  let profileDisplayName = '';
  let inspectedMfa: MfaMethod[] = [];
  let identityPolicies: IdentityClientPolicy[] = [];
  let inspectedMfaOverrides: UserMfaPolicyOverride[] = [];
  let inspectedAttempts: UserLoginAttemptPage | null = null;
  let loginProtectionPolicy: LoginProtectionPolicy = { maxFailedAttempts: 10, lockoutSeconds: 600 };
  let totpEnrollment: AdminTotpEnrollment | null = null;
  let totpCompletion: TotpEnrollmentCompletion | null = null;
  let totpCode = '';
  let totpTestMethod: MfaMethod | null = null;
  let totpTestCode = '';
  let inspectedEvidence: IdentityOperationalRecord[] = [];
  let inspectorLoading = false;
  let targetStatus: IdentityStatus = RecordStatus.Active;
  let reasonCode = 'superadmin_change';
  let sessionUser: UserIdentity | null = null;
  let sessionView: SessionView = RecordStatus.Active;
  let sessionResult: UserSessionPage | null = null;
  let sessionLoading = false;
  let saving = false;
  let copiedIdentityValue = '';
  let copiedIdentityTimer: ReturnType<typeof setTimeout>;
  let selectedUserIds = new Set<string>();
  let createForm = { username: '', displayName: '', password: '', activateImmediately: true, requirePasswordChange: true };
  let importFile: File | null = null;
  let importResult: BulkUserImportResponse | null = null;
  let importForm = { initialPassword: '', activateImmediately: true, requirePasswordChange: true };
  let resetResult: BulkPasswordResetResponse | null = null;
  let resetForm = { newPassword: '', confirmation: '', requirePasswordChange: true, reasonCode: 'hr_bulk_reset' };

  $: if (error) { showError(error, 'Identity operation failed'); error = ''; }

  const minimumPasswordLength = 9;
  const maximumPasswordLength = 1024;
  const pageSizes = [10, 20, 30, 40, 50];

  const statuses: IdentityStatus[] = [RecordStatus.Pending, RecordStatus.Active, RecordStatus.Locked, RecordStatus.Suspended, RecordStatus.Retired];

  function userDialogOpen() {
    return showCreate || showImport || showReset || inspectedUser !== null || sessionUser !== null;
  }

  function openCreateDialog() { error = ''; showCreate = true; }
  function closeCreateDialog() { error = ''; showCreate = false; }
  function openImportDialog() { error = ''; importResult = null; showImport = true; }
  function closeImportDialog() { error = ''; showImport = false; }
  function openResetDialog() { error = ''; resetResult = null; showReset = true; }
  function closeResetDialog() { error = ''; showReset = false; }

  onMount(() => { void load(); });

  async function load(requestedPage = page) {
    loading = true;
    error = '';
    try {
      let result = await adminApi.users(
        query,
        statusFilter,
        activityFilter,
        sortOrder,
        requestedPage,
        pageSize
      );
      if (result.users.length === 0 && result.page > 1) {
        result = await adminApi.users(query, statusFilter, activityFilter, sortOrder, result.page - 1, pageSize);
      }
      users = result.users;
      page = result.page;
      pageSize = result.pageSize;
      hasNext = result.hasNext;
      const visible = new Set(users.map(user => user.userId));
      selectedUserIds = new Set([...selectedUserIds].filter(userId => visible.has(userId)));
      if (sessionUser && !visible.has(sessionUser.userId)) {
        sessionUser = null;
        sessionResult = null;
      }
    } catch (reason) {
      error = message(reason);
    } finally {
      loading = false;
    }
  }

  async function createUser() {
    saving = true;
    error = '';
    try {
      await adminApi.createUser(createForm);
      createForm = { username: '', displayName: '', password: '', activateImmediately: true, requirePasswordChange: true };
      showCreate = false;
      await load();
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  function toggleSelection(userId: string) {
    const next = new Set(selectedUserIds);
    next.has(userId) ? next.delete(userId) : next.add(userId);
    selectedUserIds = next;
  }

  function toggleAllVisible() {
    const allSelected = users.length > 0 && users.every(user => selectedUserIds.has(user.userId));
    selectedUserIds = allSelected ? new Set() : new Set(users.map(user => user.userId));
  }

  function chooseImportFile(event: Event) {
    importFile = (event.currentTarget as HTMLInputElement).files?.[0] ?? null;
    importResult = null;
  }

  async function importUsers() {
    if (!importFile) return;
    saving = true;
    error = '';
    importResult = null;
    try {
      importResult = await adminApi.importUsers(importFile, importForm);
      notice = `Created ${importResult.created} of ${importResult.totalRows} identities.`;
      await load();
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function resetPasswords() {
    if (selectedUserIds.size === 0) return;
    if (resetForm.newPassword !== resetForm.confirmation) {
      error = 'The temporary password and confirmation do not match.';
      return;
    }

    saving = true;
    error = '';
    resetResult = null;
    try {
      resetResult = await adminApi.resetPasswords({
        userIds: [...selectedUserIds],
        newPassword: resetForm.newPassword,
        requirePasswordChange: resetForm.requirePasswordChange,
        reasonCode: resetForm.reasonCode
      });
      const resetIds = new Set(resetResult.users.filter(item => item.succeeded).map(item => item.userId));
      selectedUserIds = new Set([...selectedUserIds].filter(userId => !resetIds.has(userId)));
      notice = `Reset ${resetResult.reset} of ${resetResult.totalUsers} passwords. Existing sessions for successful users were revoked.`;
      resetForm = { newPassword: '', confirmation: '', requirePasswordChange: true, reasonCode: 'hr_bulk_reset' };
      showReset = false;
      await load();
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function changeStatus() {
    if (!inspectedUser) return;
    const user = inspectedUser;
    saving = true;
    error = '';
    try {
      await adminApi.changeUserStatus(user.userId, targetStatus, reasonCode);
      inspectedUser = { ...user, status: targetStatus };
      notice = `Changed ${user.displayName} to ${statusLabel(targetStatus)}.`;
      await load(page);
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function restoreUser(user: UserIdentity) {
    if (!await requestConfirmation({
      title: `Restore ${user.displayName}?`,
      message: 'The identity becomes active again, but previously revoked sessions remain revoked.',
      confirmLabel: 'Restore identity'
    })) return;

    saving = true;
    error = '';
    try {
      await adminApi.restoreUser(user.userId);
      notice = `Restored ${user.displayName}.`;
      if (inspectedUser?.userId === user.userId) {
        inspectedUser = { ...inspectedUser, status: RecordStatus.Active };
        targetStatus = RecordStatus.Active;
      }
      await load(page);
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function permanentlyDeleteUser(user: UserIdentity) {
    if (!await requestConfirmation({
      title: `Permanently delete ${user.displayName}?`,
      message: `${user.username ?? user.userId}\n\nThis removes the Kida identity, credentials, profile, sessions, MFA, recovery, and verification data. This action cannot be undone.`,
      confirmLabel: 'Permanently delete',
      tone: 'danger'
    })) return;

    saving = true;
    error = '';
    try {
      await adminApi.permanentlyDeleteUser(user.userId);
      notice = `Permanently deleted ${user.displayName}.`;
      selectedUserIds.delete(user.userId);
      selectedUserIds = new Set(selectedUserIds);
      if (inspectedUser?.userId === user.userId) inspectedUser = null;
      await load(page);
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function openSessions(user: UserIdentity) {
    error = '';
    sessionUser = user;
    sessionView = RecordStatus.Active;
    sessionResult = null;
    await loadSessions(user.userId, RecordStatus.Active, 1);
  }

  function closeSessions() {
    error = '';
    sessionUser = null;
    sessionResult = null;
  }

  function closeControl() {
    inspectedUser = null;
    error = '';
    notice = '';
  }

  async function openControl(user: UserIdentity, section: ControlSection = 'profile') {
    inspectedUser = user;
    controlSection = section;
    lifecycleSection = 'identity';
    targetStatus = user.status === RecordStatus.Active ? RecordStatus.Suspended : RecordStatus.Active;
    reasonCode = 'superadmin_change';
    inspectedProfile = null;
    profileDisplayName = user.displayName;
    inspectedMfa = [];
    identityPolicies = [];
    inspectedMfaOverrides = [];
    inspectedAttempts = null;
    totpEnrollment = null;
    totpCompletion = null;
    totpCode = '';
    totpTestMethod = null;
    totpTestCode = '';
    inspectedEvidence = [];
    inspectorLoading = true;
    error = '';
    notice = '';
    try {
      const [profile, mfa, attempts, contacts, origins, federation, challenges, grants, policies, mfaOverrides, protectionPolicy] = await Promise.all([
        adminApi.userProfile(user.userId),
        adminApi.userMfa(user.userId),
        adminApi.userLoginAttempts(user.userId, 1, 10),
        adminApi.extended ? adminApi.identityOperations('Contacts', user.userId, '', 1, 10) : Promise.resolve({ records: [] }),
        adminApi.extended ? adminApi.identityOperations('Origins', user.userId, '', 1, 10) : Promise.resolve({ records: [] }),
        adminApi.extended ? adminApi.identityOperations('Federation', user.userId, '', 1, 10) : Promise.resolve({ records: [] }),
        adminApi.extended ? adminApi.identityOperations('VerificationChallenges', user.userId, '', 1, 10) : Promise.resolve({ records: [] }),
        adminApi.extended ? adminApi.identityOperations('VerificationGrants', user.userId, '', 1, 10) : Promise.resolve({ records: [] }),
        adminApi.extended ? adminApi.identityClientPolicies() : Promise.resolve([]),
        adminApi.extended ? adminApi.userMfaPolicyOverrides(user.userId) : Promise.resolve([]),
        adminApi.loginProtectionPolicy()
      ]);
      if (inspectedUser?.userId !== user.userId) return;
      inspectedProfile = profile;
      profileDisplayName = profile.displayName;
      inspectedMfa = mfa;
      inspectedAttempts = attempts;
      identityPolicies = policies;
      inspectedMfaOverrides = mfaOverrides;
      loginProtectionPolicy = protectionPolicy;
      inspectedEvidence = [
        ...contacts.records,
        ...origins.records,
        ...federation.records,
        ...challenges.records,
        ...grants.records
      ].sort((left, right) => new Date(right.occurredAt).getTime() - new Date(left.occurredAt).getTime());
    } catch (reason) {
      if (inspectedUser?.userId === user.userId) error = message(reason);
    } finally {
      if (inspectedUser?.userId === user.userId) inspectorLoading = false;
    }
  }

  async function loadLoginAttempts(requestedPage: number) {
    if (!inspectedUser || requestedPage < 1) return;
    try {
      inspectedAttempts = await adminApi.userLoginAttempts(inspectedUser.userId, requestedPage, 10);
    } catch (reason) { error = message(reason); }
  }

  async function saveDisplayName() {
    if (!inspectedUser || !inspectedProfile) return;
    const displayName = profileDisplayName.trim().replace(/\s+/g, ' ');
    if (!displayName || displayName.length > 250) {
      error = 'Display name is required and cannot exceed 250 characters.';
      return;
    }

    saving = true;
    error = '';
    notice = '';
    const userId = inspectedUser.userId;
    try {
      const profile = await adminApi.updateUserDisplayName(userId, displayName);
      if (inspectedUser?.userId !== userId) return;
      inspectedProfile = profile;
      profileDisplayName = profile.displayName;
      inspectedUser = { ...inspectedUser, displayName: profile.displayName };
      users = users.map(user => user.userId === userId ? { ...user, displayName: profile.displayName } : user);
      notice = `Display name changed to ${profile.displayName}.`;
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  function resetPasswordForInspectedUser() {
    if (!inspectedUser) return;
    selectedUserIds = new Set([inspectedUser.userId]);
    openResetDialog();
  }

  async function releaseLoginProtection() {
    if (!inspectedUser || inspectedUser.status !== RecordStatus.Locked) return;
    if (!await requestConfirmation({
      title: `Release sign-in lock for ${inspectedUser.displayName}?`,
      message: 'The account can attempt authentication again. Login-attempt audit history will be retained.',
      confirmLabel: 'Release lock'
    })) return;
    saving = true; error = '';
    try {
      await adminApi.releaseUserLoginProtection(inspectedUser.userId);
      notice = `Released the sign-in lock for ${inspectedUser.displayName}.`;
      inspectedUser = { ...inspectedUser, status: RecordStatus.Active };
      await load(page);
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
  }

  async function beginTotpEnrollment(replaceMethodId: string | null = null) {
    if (!inspectedUser) return;
    if (!await requestConfirmation({
      title: `${replaceMethodId ? 'Replace' : 'Enroll'} authenticator?`,
      message: `This creates a real authenticator credential for ${inspectedUser.displayName}, not a simulation.\n\nA replacement leaves the current authenticator active until the new code is verified.`,
      confirmLabel: replaceMethodId ? 'Replace authenticator' : 'Start enrollment'
    })) return;
    saving = true; error = ''; totpCompletion = null; totpCode = '';
    try {
      totpEnrollment = await adminApi.beginUserTotpEnrollment(
        inspectedUser.userId,
        `${inspectedUser.username ?? inspectedUser.displayName} (Kida)`,
        replaceMethodId);
      inspectedMfa = await adminApi.userMfa(inspectedUser.userId);
    } catch (reason) {
      error = message(reason);
      inspectedMfa = await adminApi.userMfa(inspectedUser.userId).catch(() => inspectedMfa);
    }
    finally { saving = false; }
  }

  function userMfaRequirement(policy: IdentityClientPolicy): 'inherit' | 'none' | 'required' {
    return inspectedMfaOverrides.find(item =>
      item.clientId === policy.clientId && item.resource === policy.resource)?.requirement ?? 'inherit';
  }

  function currentMfaMethods(): MfaMethod[] {
    return inspectedMfa.filter(method => method.status === RecordStatus.Active || method.status === RecordStatus.Pending);
  }

  function emailContactRecords(): IdentityOperationalRecord[] {
    return inspectedEvidence.filter(record => record.area === 'Contacts' && record.type === 'email');
  }

  function usernameLooksLikeEmail(username: string | null): username is string {
    return !!username && /^[^@\s]+@[^@\s]+$/.test(username);
  }

  async function changeUserMfaRequirement(
    policy: IdentityClientPolicy,
    requirement: 'inherit' | 'none' | 'required'
  ) {
    if (!inspectedUser) return;
    if (requirement === 'none' && !await requestConfirmation({
      title: `Disable MFA for ${inspectedUser.displayName}?`,
      message: `This exception applies only when the identity uses ${policy.resource}.\n\nIt takes priority over that client’s mailbox-domain and default MFA policies. The authenticator remains enrolled for other clients.`,
      confirmLabel: 'Set No MFA',
      tone: 'danger'
    })) return;
    saving = true; error = '';
    try {
      if (requirement === 'inherit') {
        await adminApi.deleteUserMfaPolicyOverride(inspectedUser.userId, policy.clientId, policy.resource);
      } else {
        await adminApi.setUserMfaPolicyOverride(inspectedUser.userId, policy.clientId, policy.resource, requirement);
      }
      inspectedMfaOverrides = await adminApi.userMfaPolicyOverrides(inspectedUser.userId);
      notice = requirement === 'inherit'
        ? `Restored inherited MFA policy for ${policy.resource}.`
        : `Set the identity MFA override to ${requirement === 'none' ? 'No MFA' : 'Require MFA'} for ${policy.resource}.`;
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
  }

  async function confirmTotpEnrollment() {
    if (!inspectedUser || !totpEnrollment) return;
    saving = true; error = '';
    try {
      totpCompletion = await adminApi.confirmUserTotpEnrollment(
        inspectedUser.userId, totpEnrollment.ticket, totpCode);
      notice = `Authenticator verified and activated for ${inspectedUser.displayName}.`;
      inspectedMfa = await adminApi.userMfa(inspectedUser.userId);
      totpEnrollment = null; totpCode = '';
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
  }

  async function cancelTotpEnrollment() {
    if (!inspectedUser || !totpEnrollment) return;
    const enrollment = totpEnrollment;
    totpEnrollment = null; totpCode = '';
    try {
      await adminApi.retireUserMfaMethod(inspectedUser.userId, enrollment.methodId);
      inspectedMfa = await adminApi.userMfa(inspectedUser.userId);
    } catch (reason) { error = message(reason); }
  }

  function beginTotpTest(method: MfaMethod) {
    totpTestMethod = method;
    totpTestCode = '';
    error = '';
  }

  async function testTotp() {
    if (!inspectedUser || !totpTestMethod || !/^[0-9]{6}$/.test(totpTestCode)) return;
    saving = true; error = '';
    try {
      await adminApi.testUserTotp(inspectedUser.userId, totpTestMethod.methodId, totpTestCode);
      notice = `Authenticator code verified for ${inspectedUser.displayName}.`;
      inspectedMfa = await adminApi.userMfa(inspectedUser.userId);
      totpTestMethod = null;
      totpTestCode = '';
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
  }

  async function retireMfaMethod(method: MfaMethod) {
    if (!inspectedUser || !await requestConfirmation({
      title: `Retire ${method.label ?? method.kind}?`,
      message: `The authenticator will stop working immediately for ${inspectedUser.displayName}. Its audit record will be retained.`,
      confirmLabel: method.status === RecordStatus.Pending ? 'Discard pending' : 'Retire authenticator',
      tone: 'danger'
    })) return;
    saving = true; error = '';
    try {
      await adminApi.retireUserMfaMethod(inspectedUser.userId, method.methodId);
      inspectedMfa = await adminApi.userMfa(inspectedUser.userId);
      notice = `Retired the authenticator method.`;
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
  }

  async function overrideEmailVerification(record: IdentityOperationalRecord) {
    if (!inspectedUser || !record.recordId || record.area !== 'Contacts' || record.type !== 'email' || record.status !== RecordStatus.Pending) return;
    if (!await requestConfirmation({
      title: 'Break-glass verify this email?',
      message: `${record.detail ?? 'This email address'} will be marked as verified for ${inspectedUser.displayName}.\n\nThis administratively bypasses OTP/link proof and is audit-significant. It changes only email verification; it does not create a password or activate a pending identity.`,
      confirmLabel: 'Break-glass verify',
      tone: 'danger'
    })) return;

    saving = true;
    error = '';
    try {
      await adminApi.overrideEmailVerification(inspectedUser.userId, record.recordId);
      const userName = inspectedUser.displayName;
      const currentSection = controlSection;
      await openControl(inspectedUser, currentSection);
      notice = `Break-glass email verification completed for ${userName}.`;
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function recordLoginEmailContact() {
    if (!inspectedUser || !usernameLooksLikeEmail(inspectedUser.username) || emailContactRecords().length > 0) return;
    if (!await requestConfirmation({
      title: 'Record login as an email contact?',
      message: `${inspectedUser.username} will be added as a pending email contact. This records the address but does not prove mailbox ownership. Complete normal verification or use the separate break-glass action afterward.`,
      confirmLabel: 'Record pending email',
      tone: 'default'
    })) return;

    saving = true;
    error = '';
    try {
      await adminApi.recordLoginEmailContact(inspectedUser.userId);
      const userName = inspectedUser.displayName;
      const currentSection = controlSection;
      await openControl(inspectedUser, currentSection);
      notice = `Pending email contact recorded for ${userName}.`;
    } catch (reason) {
      error = message(reason);
    } finally {
      saving = false;
    }
  }

  async function loadSessions(userId: string, view: SessionView, page: number) {
    sessionLoading = true;
    error = '';
    try {
      let result = await adminApi.userSessions(userId, view, page);
      if (result.sessions.length === 0 && result.page > 1) {
        result = await adminApi.userSessions(userId, view, result.page - 1);
      }
      if (sessionUser?.userId === userId && sessionView === view) sessionResult = result;
    } catch (reason) {
      if (sessionUser?.userId === userId && sessionView === view) error = message(reason);
    } finally {
      if (sessionUser?.userId === userId && sessionView === view) sessionLoading = false;
    }
  }

  async function changeSessionView(view: SessionView) {
    if (!sessionUser || sessionView === view) return;
    sessionView = view;
    sessionResult = null;
    await loadSessions(sessionUser.userId, view, 1);
  }

  async function changeSessionPage(page: number) {
    if (!sessionUser || page < 1 || page === sessionResult?.page || (page > (sessionResult?.page ?? 1) && !sessionResult?.hasNext)) return;
    await loadSessions(sessionUser.userId, sessionView, page);
  }

  async function revoke(sessionId: string, userId: string) {
    const requestedView = sessionView;
    const requestedPage = sessionResult?.page ?? 1;
    try {
      await adminApi.revokeSession(sessionId);
      if (sessionUser?.userId !== userId || sessionView !== requestedView) return;
      await loadSessions(userId, requestedView, requestedPage);
    } catch (reason) {
      error = message(reason);
    }
  }

  function message(reason: unknown) {
    return reason instanceof ApiError ? reason.message : 'The identity service is unavailable.';
  }

  function date(value: string | null) {
    return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Never';
  }

  async function copyIdentityValue(key: string, value: string) {
    if (await copyText(value)) {
      copiedIdentityValue = key;
      clearTimeout(copiedIdentityTimer);
      copiedIdentityTimer = setTimeout(() => { copiedIdentityValue = ''; }, 1400);
    }
  }

  function isActiveSession(session: UserSession) {
    return session.status === RecordStatus.Active && new Date(session.expiresAt).getTime() > Date.now();
  }

  function sessionStatus(session: UserSession) {
    return isActiveSession(session) ? RecordStatus.Active : session.status === RecordStatus.Active ? RecordStatus.Expired : session.status;
  }

  async function changeUserPage(requestedPage: number) {
    if (requestedPage < 1 || requestedPage === page || (requestedPage > page && !hasNext)) return;
    await load(requestedPage);
  }
</script>

<section class="page">
  <header class="page-header">
    <div><p class="eyebrow">Identity authority</p><h1>Users & sessions</h1></div>
    <div class="page-actions">
      {#if adminApi.extended}<button class="quiet" onclick={openImportDialog}>⇧ Import CSV</button>{/if}
      <button class="quiet" disabled={selectedUserIds.size === 0} onclick={openResetDialog}>Reset selected ({selectedUserIds.size})</button>
      <button class="primary" onclick={openCreateDialog}>＋ Add identity</button>
    </div>
  </header>

  <div class="toolbar panel compact">
    <div class="search-field"><span>⌕</span><input bind:value={query} onkeydown={(event) => event.key === 'Enter' && void load(1)} placeholder="Search name, username, or UUID" /></div>
    <select bind:value={statusFilter} onchange={() => void load(1)} aria-label="Filter by status">
      <option value="">All lifecycle states</option>
      {#each statuses as status}<option value={status}>{statusLabel(status)}</option>{/each}
    </select>
    <select bind:value={activityFilter} onchange={() => void load(1)} aria-label="Filter by sign-in or password state">
      <option value="All">All activity states</option>
      <option value="NeverLoggedIn">Never logged in</option>
      <option value="HasLoggedIn">Has logged in</option>
      <option value="PasswordChangeRequired">Password change required</option>
    </select>
    <select bind:value={sortOrder} onchange={() => void load(1)} aria-label="Sort identities">
      <option value="CreatedNewest">Newest identities</option>
      <option value="CreatedOldest">Oldest identities</option>
      <option value="LastLoginNewest">Latest login first</option>
      <option value="LastLoginOldest">Oldest login first</option>
    </select>
    <select bind:value={pageSize} onchange={() => void load(1)} aria-label="Identities per page">
      {#each pageSizes as size}<option value={size}>{size} per page</option>{/each}
    </select>
    <button class="quiet" onclick={() => void load(page)}>Refresh</button>
  </div>

  {#if notice && !userDialogOpen()}<div class="notice success" role="status"><strong>Completed</strong><span>{notice}</span><button aria-label="Dismiss" onclick={() => notice = ''}>×</button></div>{/if}

  <div class="panel table-panel">
    <div class="panel-heading"><div><p class="eyebrow">Directory</p><h3>Identity records</h3></div><small>{pageSize} records per page · UUIDv7 public references</small></div>
    <div class="table-wrap">
      <table class="identity-directory">
        <thead><tr><th><span class="identity-select-all"><input type="checkbox" aria-label="Select all visible users" checked={users.length > 0 && users.every(user => selectedUserIds.has(user.userId))} onchange={toggleAllVisible} />Identity</span></th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
          {#if loading}
            <tr><td colspan="3"><div class="empty-state">Loading identity records…</div></td></tr>
          {:else if users.length === 0}
            <tr><td colspan="3"><div class="empty-state">No identities match this view.</div></td></tr>
          {:else}
            {#each users as user}
              <tr class="identity-primary-row" class:selected-row={selectedUserIds.has(user.userId)}>
                <td><div class="identity-primary-cell"><input type="checkbox" aria-label={`Select ${user.displayName}`} checked={selectedUserIds.has(user.userId)} onchange={() => toggleSelection(user.userId)} /><div class="identity-cell"><span>{user.displayName.slice(0, 1).toUpperCase()}</span><div><button type="button" class="copy-link identity-copy-line identity-name" class:copied={copiedIdentityValue === `name:${user.userId}`} title={`Copy ${user.displayName}`} aria-label={`Copy display name ${user.displayName}`} onclick={() => void copyIdentityValue(`name:${user.userId}`, user.displayName)}>{copiedIdentityValue === `name:${user.userId}` ? 'Copied' : user.displayName}</button></div></div></div></td>
                <td><span class="status-pill {statusClass(user.status)}">{statusLabel(user.status)}</span>{#if user.passwordChangeRequired}<small class="password-flag">Password change required</small>{/if}</td>
                <td title={date(user.createdAt)}>{date(user.createdAt)}</td>
              </tr>
              <tr class="identity-secondary-row" class:selected-row={selectedUserIds.has(user.userId)}>
                <td colspan="3"><div class="identity-secondary-content"><div class="identity-meta-lines">{#if user.username}<button type="button" class="copy-link identity-copy-line" class:copied={copiedIdentityValue === `username:${user.userId}`} title={`Copy ${user.username}`} aria-label={`Copy email or username ${user.username}`} onclick={() => void copyIdentityValue(`username:${user.userId}`, user.username!)}>{copiedIdentityValue === `username:${user.userId}` ? 'Copied' : user.username}</button>{:else}<span class="identity-copy-line">No username</span>{/if}<button type="button" class="copy-link identity-copy-line" class:copied={copiedIdentityValue === `id:${user.userId}`} title={`Copy ${user.userId}`} aria-label={`Copy user ID ${user.userId}`} onclick={() => void copyIdentityValue(`id:${user.userId}`, user.userId)}>{copiedIdentityValue === `id:${user.userId}` ? 'Copied' : user.userId}</button></div><div class="row-actions"><button onclick={() => void openSessions(user)}>Sessions</button>{#if adminApi.extended}<button onclick={() => onAccess(user.userId)}>Access</button>{/if}<button class="primary-row-action" onclick={() => void openControl(user)}>Control</button></div></div></td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
    {#if users.length > 0}
      <div class="session-pagination table-pagination">
        <small>Showing {(page - 1) * pageSize + 1}–{(page - 1) * pageSize + users.length}</small>
        <div><button disabled={loading || page <= 1} onclick={() => void changeUserPage(page - 1)}>Previous</button><span>Page {page}</span><button disabled={loading || !hasNext} onclick={() => void changeUserPage(page + 1)}>Next</button></div>
      </div>
    {/if}
  </div>
</section>

{#if sessionUser}
  <div class="modal-backdrop" role="presentation" onclick={(event) => event.currentTarget === event.target && closeSessions()}>
    <div class="modal session-modal" role="dialog" aria-modal="true" aria-labelledby="sessions-title">
      <div class="modal-head">
        <div><p class="eyebrow">Identity sessions</p><h2 id="sessions-title">{sessionUser.displayName}</h2><small>{sessionUser.username ?? 'No username'} · {sessionUser.userId}</small></div>
        <button class="icon-button" aria-label="Close sessions" onclick={closeSessions}>×</button>
      </div>
      <div class="session-panel">
        <div class="session-toolbar">
          <div class="session-tabs" role="tablist" aria-label="Session view">
            <button class:active={sessionView === RecordStatus.Active} role="tab" aria-selected={sessionView === RecordStatus.Active} onclick={() => void changeSessionView(RecordStatus.Active)}>Active</button>
            <button class:active={sessionView === 'all'} role="tab" aria-selected={sessionView === 'all'} onclick={() => void changeSessionView('all')}>All</button>
          </div>
          <small>{sessionResult?.sessions.length ?? 0} shown · {sessionView === RecordStatus.Active ? 'active only' : 'all states'}</small>
        </div>
        {#if sessionLoading}
          <p class="session-empty">Loading sessions…</p>
        {:else if (sessionResult?.sessions.length ?? 0) === 0}
          <p class="session-empty">{sessionView === RecordStatus.Active ? 'No active sessions for this identity.' : 'No sessions recorded for this identity.'}</p>
        {:else}
          <div class="session-list">
            {#each sessionResult?.sessions ?? [] as session}
              <div class="session-item">
                <span class:active-dot={isActiveSession(session)}></span>
                <div><strong>{sessionStatus(session)}{session.resource ? ` · ${session.resource}` : ''}</strong><small>{session.sessionId} · client {session.applicationId ?? session.clientId ?? 'not recorded'} · last seen {date(session.lastSeenAt)} · expires {date(session.expiresAt)}{session.endedAt ? ` · ended ${date(session.endedAt)}` : ''}</small></div>
                {#if isActiveSession(session)}<button class="danger-text" onclick={() => revoke(session.sessionId, sessionUser!.userId)}>Revoke</button>{/if}
              </div>
            {/each}
          </div>
        {/if}
        {#if sessionResult && sessionResult.sessions.length > 0}
          <div class="session-pagination">
            <small>Showing {(sessionResult.page - 1) * sessionResult.pageSize + 1}–{(sessionResult.page - 1) * sessionResult.pageSize + sessionResult.sessions.length}</small>
            <div><button disabled={sessionLoading || sessionResult.page <= 1} onclick={() => void changeSessionPage(sessionResult!.page - 1)}>Previous</button><span>Page {sessionResult.page}</span><button disabled={sessionLoading || !sessionResult.hasNext} onclick={() => void changeSessionPage(sessionResult!.page + 1)}>Next</button></div>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

{#if inspectedUser}
  <div class="modal-backdrop" role="presentation" onclick={(event) => event.currentTarget === event.target && closeControl()}>
    <div class="modal identity-control-modal" role="dialog" aria-modal="true" aria-labelledby="control-title">
      <div class="modal-head control-modal-head">
        <div><p class="eyebrow">Identity control</p><h2 id="control-title">{inspectedUser.displayName}</h2><small>{inspectedUser.username ?? 'No username'} · {inspectedUser.userId}</small></div>
        <div class="control-head-actions"><span class="status-pill {statusClass(inspectedUser.status)}">{statusLabel(inspectedUser.status)}</span><button class="icon-button" aria-label="Close identity control" onclick={closeControl}>×</button></div>
      </div>
      <div class="identity-control-layout">
        <nav class="control-nav" aria-label="Identity controls">
          <button class:active={controlSection === 'profile'} aria-current={controlSection === 'profile' ? 'page' : undefined} onclick={() => controlSection = 'profile'}><span>Profile</span><small>Identity details</small></button>
          <button class:active={controlSection === 'mfa'} aria-current={controlSection === 'mfa' ? 'page' : undefined} onclick={() => controlSection = 'mfa'}><span>MFA</span><small>Authenticators</small></button>
          <button class:active={controlSection === 'attempts'} aria-current={controlSection === 'attempts' ? 'page' : undefined} onclick={() => controlSection = 'attempts'}><span>Attempts</span><small>Sign-in evidence</small></button>
          <button class:active={controlSection === 'lifecycle'} aria-current={controlSection === 'lifecycle' ? 'page' : undefined} onclick={() => controlSection = 'lifecycle'}><span>Lifecycle</span><small>Status & verification</small></button>
        </nav>

        <div class="control-content">
          {#if notice}<div class="notice success" role="status"><strong>Completed</strong><span>{notice}</span><button aria-label="Dismiss" onclick={() => notice = ''}>×</button></div>{/if}
          {#if inspectorLoading}
            <div class="empty-state">Loading identity controls…</div>
          {:else if controlSection === 'profile'}
            <article class="panel compact control-panel">
              <div class="panel-heading"><div><p class="eyebrow">Profile</p><h3>{inspectedProfile?.preferredName ?? inspectedProfile?.displayName ?? inspectedUser.displayName}</h3></div></div>
              <form class="profile-display-name-form" onsubmit={(event) => { event.preventDefault(); void saveDisplayName(); }}>
                <label>Display name<input bind:value={profileDisplayName} required maxlength="250" autocomplete="off" /></label>
                <button class="primary" disabled={saving || !profileDisplayName.trim() || profileDisplayName.trim().replace(/\s+/g, ' ') === inspectedProfile?.displayName}>{saving ? 'Saving…' : 'Save display name'}</button>
              </form>
              <dl class="detail-list">
                <div><dt>Username</dt><dd>{inspectedUser.username ?? 'Not assigned'}</dd></div>
                <div><dt>Display name</dt><dd>{inspectedProfile?.displayName ?? inspectedUser.displayName}</dd></div>
                <div><dt>Preferred name</dt><dd>{inspectedProfile?.preferredName ?? '-'}</dd></div>
                <div><dt>Given / family</dt><dd>{inspectedProfile?.givenName ?? '-'} / {inspectedProfile?.familyName ?? '-'}</dd></div>
                <div><dt>Locale / time zone</dt><dd>{inspectedProfile?.locale ?? '-'} / {inspectedProfile?.timeZone ?? '-'}</dd></div>
                <div><dt>Password state</dt><dd>{inspectedUser.passwordChangeRequired ? 'Change required' : 'Current'}</dd></div>
                <div><dt>Last authentication</dt><dd>{date(inspectedUser.lastAuthenticatedAt)}</dd></div>
                <div><dt>Created</dt><dd>{date(inspectedUser.createdAt)}</dd></div>
              </dl>
            </article>
          {:else if controlSection === 'mfa'}
            <article class="panel compact control-panel">
              <div class="panel-heading"><div><p class="eyebrow">MFA posture</p><h3>{currentMfaMethods().length} current methods</h3></div><button class="quiet" disabled={saving} onclick={() => void beginTotpEnrollment()}>{currentMfaMethods().some(method => method.kind === 'Totp' && method.status === RecordStatus.Pending) ? 'Restart enrollment' : 'Enroll authenticator'}</button></div>
              <p class="form-note mfa-ownership-note">Authenticators belong to this identity. The application login policy decides when an enrolled method is required. The QR is shown only during enrollment or replacement and is not recoverable afterward.</p>
              {#if adminApi.extended}<div class="mfa-policy-panel">
                <div><strong>Identity enforcement exceptions</strong><p class="form-note">Domain rules are configured under Federation. An identity exception applies only to the selected client and audience, and takes priority over the domain rule.</p></div>
                <div class="mfa-policy-list">
                  {#each identityPolicies as policy}
                    <label><span><strong>{policy.resource}</strong><small>Client {policy.clientId} · inherited default: {policy.mfaRequirement}</small></span><select value={userMfaRequirement(policy)} disabled={saving} onchange={(event) => void changeUserMfaRequirement(policy, (event.currentTarget as HTMLSelectElement).value as 'inherit' | 'none' | 'required')}><option value="inherit">Inherit domain/client policy</option><option value="required">Require MFA</option><option value="none">No MFA (exception)</option></select></label>
                  {:else}<p class="muted control-empty">No client/audience onboarding policies are configured. Add one under Federation before creating an identity exception.</p>{/each}
                </div>
              </div>
              {/if}
              <div class="security-list">
                {#each currentMfaMethods() as method}
                  <div><span class="status-pill {method.status === RecordStatus.Active ? 'active' : 'pending'}">{statusLabel(method.status)}</span><div><strong>{method.kind}{method.label ? ` · ${method.label}` : ''}</strong><small>Verified {date(method.verifiedAt)} · last used {date(method.lastUsedAt)}</small>{#if method.kind === 'Totp' && method.status === RecordStatus.Pending}<small>The QR ticket is one-time and cannot be recovered. Discard this method or restart enrollment.</small>{/if}</div>{#if method.kind === 'Totp' && method.status === RecordStatus.Active}<div class="row-actions"><button class="primary-row-action" disabled={saving} onclick={() => beginTotpTest(method)}>Test</button><button disabled={saving} onclick={() => void beginTotpEnrollment(method.methodId)}>Replace</button><button class="danger-text" disabled={saving} onclick={() => void retireMfaMethod(method)}>Retire</button></div>{:else if method.kind === 'Totp' && method.status === RecordStatus.Pending}<div class="row-actions"><button class="danger-text" disabled={saving} onclick={() => void retireMfaMethod(method)}>Discard pending</button></div>{/if}</div>
                {:else}<p class="muted control-empty">No active or pending MFA methods are registered.</p>{/each}
              </div>
              {#if inspectedMfa.length > currentMfaMethods().length}<p class="form-note">{inspectedMfa.length - currentMfaMethods().length} retired method(s) remain in operational history and are hidden here.</p>{/if}
              {#if totpTestMethod}
                <div class="mfa-test-panel">
                  <h3>Test active authenticator</h3>
                  <p class="form-note">Enter the current six-digit code for <strong>{totpTestMethod.label ?? 'this authenticator'}</strong>. Identity performs the same verification used during login and consumes this 30-second code to prevent replay.</p>
                  <label>Current authenticator code<input bind:value={totpTestCode} inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" /></label>
                  <div class="modal-actions"><button class="quiet" disabled={saving} onclick={() => { totpTestMethod = null; totpTestCode = ''; }}>Cancel</button><button class="primary" disabled={saving || !/^[0-9]{6}$/.test(totpTestCode)} onclick={() => void testTotp()}>{saving ? 'Testing…' : 'Test code'}</button></div>
                </div>
              {/if}
              {#if totpEnrollment}
                <div class="mfa-test-panel">
                  <h3>Scan this authenticator QR code</h3>
                  <p class="form-note danger-note">This is a live enrollment. Scan the QR with Microsoft Authenticator, then verify a code. Existing MFA remains active until a replacement succeeds.</p>
                  <div class="qr-preview">{@html totpEnrollment.qrCodeSvg}</div>
                  <label>Six-digit test code<input bind:value={totpCode} inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" /></label>
                  <div class="modal-actions"><button class="quiet" onclick={() => void cancelTotpEnrollment()}>Cancel</button><button class="primary" disabled={saving || !/^[0-9]{6}$/.test(totpCode)} onclick={() => void confirmTotpEnrollment()}>Verify & activate</button></div>
                </div>
              {/if}
              {#if totpCompletion}
                <div class="bulk-result"><strong>Recovery codes - save now</strong><div class="recovery-grid">{#each totpCompletion.recoveryCodes as code}<code>{code}</code>{/each}</div></div>
              {/if}
            </article>
          {:else if controlSection === 'attempts'}
            <article class="panel table-panel control-panel">
              <div class="panel-heading"><div><p class="eyebrow">Sign-in protection</p><h3>Login attempts</h3></div>{#if inspectedUser.status === RecordStatus.Locked}<button class="quiet danger-text" disabled={saving} onclick={() => void releaseLoginProtection()}>Release lock</button>{/if}</div>
              <p class="form-note">Identity locks the account after {loginProtectionPolicy.maxFailedAttempts} consecutive invalid passwords and revokes its active sessions. Automatic locks expire after {Math.ceil(loginProtectionPolicy.lockoutSeconds / 60)} minutes. Releasing a lock restores sign-in eligibility immediately; it never erases this history.</p>
              <div class="table-wrap"><table><thead><tr><th>Outcome</th><th>Reason</th><th>Client</th><th>Attempted</th></tr></thead><tbody>
                {#each inspectedAttempts?.attempts ?? [] as attempt}<tr><td><span class="status-pill {attempt.outcome === 'success' ? 'active' : 'retired'}">{attempt.outcome}</span></td><td>{attempt.reasonCode ?? '-'}</td><td>{attempt.clientId ?? 'Not resolved'}</td><td>{date(attempt.occurredAt)}</td></tr>{:else}<tr><td colspan="4"><div class="empty-state">No login attempts are recorded for this identity.</div></td></tr>{/each}
              </tbody></table></div>
              {#if inspectedAttempts && inspectedAttempts.attempts.length > 0}<div class="session-pagination control-pagination"><small>Showing {(inspectedAttempts.page - 1) * inspectedAttempts.pageSize + 1}–{(inspectedAttempts.page - 1) * inspectedAttempts.pageSize + inspectedAttempts.attempts.length}</small><div><button disabled={inspectedAttempts.page <= 1} onclick={() => void loadLoginAttempts(inspectedAttempts!.page - 1)}>Previous</button><span>Page {inspectedAttempts.page}</span><button disabled={!inspectedAttempts.hasNext} onclick={() => void loadLoginAttempts(inspectedAttempts!.page + 1)}>Next</button></div></div>{/if}
            </article>
          {:else}
            <div class="lifecycle-stack">
              <div class="segmented lifecycle-tabs" role="tablist" aria-label="Lifecycle sections">
                {#if adminApi.extended}<button role="tab" aria-selected={lifecycleSection === 'evidence'} class:active={lifecycleSection === 'evidence'} onclick={() => lifecycleSection = 'evidence'}>Evidence</button>{/if}
                <button role="tab" aria-selected={lifecycleSection === 'identity'} class:active={lifecycleSection === 'identity'} onclick={() => lifecycleSection = 'identity'}>Identity</button>
                {#if adminApi.extended}<button role="tab" aria-selected={lifecycleSection === 'verification'} class:active={lifecycleSection === 'verification'} onclick={() => lifecycleSection = 'verification'}>Verification</button>{/if}
              </div>
              {#if lifecycleSection === 'identity'}
              <article class="panel compact control-panel">
                <div class="panel-heading"><div><p class="eyebrow">Lifecycle control</p><h3>{statusLabel(inspectedUser.status)} identity</h3></div><button class="quiet" type="button" onclick={resetPasswordForInspectedUser}>Reset password</button></div>
                {#if inspectedUser.status === RecordStatus.Retired}
                  <p class="form-note">Restore makes this identity active again. Previously revoked sessions remain revoked.</p>
                  <div class="lifecycle-actions"><button class="primary" disabled={saving} onclick={() => void restoreUser(inspectedUser!)}>Restore identity</button><button class="quiet danger-text" disabled={saving} onclick={() => void permanentlyDeleteUser(inspectedUser!)}>Delete permanently</button></div>
                {:else}
                  <form class="lifecycle-form" onsubmit={(event) => { event.preventDefault(); void changeStatus(); }}>
                    <label>New status<select bind:value={targetStatus}>{#each statuses as status}<option value={status}>{statusLabel(status)}</option>{/each}</select></label>
                    <label>Reason code<input bind:value={reasonCode} required maxlength="64" pattern="[a-zA-Z0-9_.-]+" /></label>
                    <button class="primary" disabled={saving}>{saving ? 'Applying…' : 'Apply change'}</button>
                  </form>
                  <p class="form-note">Any move away from Active revokes active sessions and refresh-token families. Retirement is reversible; permanent deletion is available only after retirement.</p>
                {/if}
              </article>
              {:else if lifecycleSection === 'verification'}
              <article class="panel compact control-panel">
                <div class="panel-heading"><div><p class="eyebrow">Emergency verification</p><h3>Email ownership</h3></div><small>{emailContactRecords().length} email contact{emailContactRecords().length === 1 ? '' : 's'}</small></div>
                <p class="form-note danger-note">Break-glass verification bypasses the normal OTP or link ceremony. Use it only after an administrator has independently confirmed mailbox ownership; Kida records the administrative attestation.</p>
                <div class="security-list">
                  {#each emailContactRecords() as contact}
                    <div><span class="status-pill {contact.status === RecordStatus.Verified ? 'active' : contact.status}">{statusLabel(contact.status)}</span><div><strong>{contact.detail ?? 'Email contact'}</strong><small>Added {date(contact.occurredAt)}{contact.completedAt ? ` · completed ${date(contact.completedAt)}` : ''}</small></div>{#if contact.status === RecordStatus.Pending && contact.recordId}<button class="danger-text" disabled={saving} onclick={() => void overrideEmailVerification(contact)}>Break-glass verify</button>{/if}</div>
                  {:else}
                    {#if usernameLooksLikeEmail(inspectedUser.username)}
                      <div class="empty-action"><p class="form-note">The login identifier <strong>{inspectedUser.username}</strong> is email-shaped but is not yet recorded as a contact. Record it as pending before verifying ownership.</p><button class="primary" disabled={saving} onclick={() => void recordLoginEmailContact()}>{saving ? 'Recording…' : 'Record pending email'}</button></div>
                    {:else}
                      <p class="muted control-empty">No email contact is recorded for this identity.</p>
                    {/if}
                  {/each}
                </div>
              </article>
              {:else}
              <article class="panel table-panel control-panel">
                <div class="panel-heading"><div><p class="eyebrow">Lifecycle evidence</p><h3>Contacts, origin, federation, and verification</h3></div><small>{inspectedEvidence.length} recent records</small></div>
                <div class="table-wrap"><table><thead><tr><th>Area</th><th>Type</th><th>Status</th><th>Context</th><th>Observed</th></tr></thead><tbody>{#each inspectedEvidence as record}<tr><td>{record.area}</td><td>{record.type}</td><td><span class="status-pill {record.status === RecordStatus.Active || record.status === RecordStatus.Verified || record.status === OperationalStatus.Linked || record.status === OperationalStatus.Recorded ? 'active' : record.status === RecordStatus.Pending ? 'pending' : ''}">{operationalStatusLabel(record.status)}</span></td><td>{record.provider ?? record.detail ?? '-'}{#if record.attempts !== null}<small>{record.attempts} attempts</small>{/if}</td><td>{date(record.occurredAt)}</td></tr>{:else}<tr><td colspan="5"><div class="empty-state">No lifecycle evidence is recorded.</div></td></tr>{/each}</tbody></table></div>
              </article>
              {/if}
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showCreate}
  <div class="modal-backdrop" role="presentation" onclick={(event) => event.currentTarget === event.target && closeCreateDialog()}>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="create-title">
      <div class="modal-head"><div><p class="eyebrow">New local identity</p><h2 id="create-title">Create user</h2></div><button class="icon-button" onclick={closeCreateDialog}>×</button></div>
      <form onsubmit={(event) => { event.preventDefault(); void createUser(); }}>
        <label>Display name<input bind:value={createForm.displayName} required maxlength="250" placeholder="Ada Lovelace" /></label>
        <label>Username<input bind:value={createForm.username} required maxlength="190" autocomplete="off" placeholder="ada@example.com" /></label>
        <label>Initial password<input bind:value={createForm.password} required minlength={minimumPasswordLength} maxlength={maximumPasswordLength} type="password" autocomplete="new-password" placeholder={`${minimumPasswordLength} characters minimum`} /></label>
        <label class="check"><input bind:checked={createForm.activateImmediately} type="checkbox" /><span><strong>Activate immediately</strong><small>Otherwise the identity remains pending.</small></span></label>
        <label class="check"><input bind:checked={createForm.requirePasswordChange} type="checkbox" /><span><strong>Require password change on next login</strong><small>No application token is issued until the temporary password is replaced.</small></span></label>
        <div class="modal-actions"><button type="button" class="quiet" onclick={closeCreateDialog}>Cancel</button><button class="primary" disabled={saving}>{saving ? 'Creating…' : 'Create identity'}</button></div>
      </form>
    </div>
  </div>
{/if}

{#if showImport}
  <div class="modal-backdrop">
    <div class="modal import-modal" role="dialog" aria-modal="true" aria-labelledby="import-title">
      <div class="modal-head"><div><p class="eyebrow">HR identity provisioning</p><h2 id="import-title">Import users from CSV</h2></div><button class="icon-button" onclick={closeImportDialog}>×</button></div>
      <form onsubmit={(event) => { event.preventDefault(); void importUsers(); }}>
        <label>CSV file<input type="file" accept=".csv,text/csv" required onchange={chooseImportFile} /></label>
        <p class="form-note"><strong>Accepted Headers:</strong> Username, Email, Email ID, Email Address, Display Name, Name, Full Name, Employee Name, Name of the Candidate, Employee ID, Employee Identifier, Staff ID</p>
        <label>Shared temporary password<input bind:value={importForm.initialPassword} required minlength={minimumPasswordLength} maxlength={maximumPasswordLength} type="password" autocomplete="new-password" placeholder={`${minimumPasswordLength} characters minimum`} /></label>
        <label class="check"><input bind:checked={importForm.activateImmediately} type="checkbox" /><span><strong>Activate imported identities</strong><small>Clear this to create them in Pending state.</small></span></label>
        <label class="check"><input bind:checked={importForm.requirePasswordChange} type="checkbox" /><span><strong>Require password change on next login</strong><small>Recommended when one temporary password is shared across the import.</small></span></label>
        <div class="modal-actions"><button type="button" class="quiet" onclick={closeImportDialog}>Close</button><button class="primary" disabled={saving || !importFile}>{saving ? 'Importing…' : 'Import identities'}</button></div>
      </form>

      {#if importResult}
        <div class="bulk-result">
          <div class="bulk-summary"><strong>{importResult.created} created</strong><span>{importResult.failed} failed · {importResult.totalRows} total</span></div>
          <div class="table-wrap compact-results"><table><thead><tr><th>Row</th><th>Employee ID</th><th>Identity</th><th>Result</th></tr></thead><tbody>
            {#each importResult.rows as row}
              <tr><td>{row.rowNumber}</td><td>{row.employeeId ?? '-'}</td><td><strong>{row.displayName}</strong><small>{row.username}</small></td><td><span class="status-pill {row.succeeded ? 'active' : 'retired'}">{row.succeeded ? 'Created' : row.errorCode}</span></td></tr>
            {/each}
          </tbody></table></div>
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if showReset}
  <div class="modal-backdrop">
    <div class="modal narrow" role="dialog" aria-modal="true" aria-labelledby="reset-title">
      <div class="modal-head"><div><p class="eyebrow">Global credential action</p><h2 id="reset-title">Reset {selectedUserIds.size} passwords</h2></div><button class="icon-button" onclick={closeResetDialog}>×</button></div>
      <form onsubmit={(event) => { event.preventDefault(); void resetPasswords(); }}>
        <label>Temporary password<input bind:value={resetForm.newPassword} required minlength={minimumPasswordLength} maxlength={maximumPasswordLength} type="password" autocomplete="new-password" /></label>
        <label>Confirm temporary password<input bind:value={resetForm.confirmation} required minlength={minimumPasswordLength} maxlength={maximumPasswordLength} type="password" autocomplete="new-password" /></label>
        <label>Reason code<input bind:value={resetForm.reasonCode} required maxlength="64" pattern="[a-zA-Z0-9_.-]+" /></label>
        <label class="check"><input bind:checked={resetForm.requirePasswordChange} type="checkbox" /><span><strong>Require password change on next login</strong><small>Selected users cannot receive normal application tokens until they replace it.</small></span></label>
        <div class="modal-actions"><button type="button" class="quiet" onclick={closeResetDialog}>Cancel</button><button class="primary" disabled={saving}>{saving ? 'Resetting…' : `Reset ${selectedUserIds.size} passwords`}</button></div>
      </form>
    </div>
  </div>
{/if}
