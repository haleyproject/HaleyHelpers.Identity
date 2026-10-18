<script lang="ts">
  import { RecordStatus, OperationalStatus, statusLabel, statusClass, operationalStatusLabel } from '../lib/statuses';
  import { onMount, onDestroy } from 'svelte';
  import IdentityWorkflows from './IdentityWorkflows.svelte';
  import { adminApi, ApiError } from '../lib/api';
  import { requestConfirmation } from '../lib/confirmation';
  import { copyText } from '../lib/clipboard';
  import { showError } from '../lib/snackbar';
  import type {
    BulkPasswordResetResponse,
    AccountEmailContact,
    BulkUserImportResponse,
    IdentityOperationalRecord,
    IdentityClientPolicy,
    IdentityStatus,
    IdentityWorkflowApplication,
    IdentityWorkflowSettings,
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

  // The host navigates to its Access page; the display name lets it label the way back.
  export let onAccess: (subjectId: string, displayName?: string) => void = () => {};

  type SessionView = RecordStatus.Active | 'all';
  // One account, one page: the directory is replaced by a full page with a left rail of sections.
  type ControlSection = 'overview' | 'security' | 'sessions' | 'attempts' | 'verification' | 'authentication' | 'lifecycle';
  const sections: Array<{ id: ControlSection; label: string; detail: string; group: 'Account' | 'Workflows' }> = [
    { id: 'overview', label: 'Overview', detail: 'Details & profile', group: 'Account' },
    { id: 'security', label: 'Security', detail: 'Authenticators & recovery codes', group: 'Account' },
    { id: 'sessions', label: 'Sessions', detail: 'Active sessions & history', group: 'Account' },
    { id: 'attempts', label: 'Sign-in attempts', detail: 'Lock state & evidence', group: 'Account' },
    { id: 'lifecycle', label: 'Lifecycle', detail: 'Status, restore, delete', group: 'Account' },
    { id: 'verification', label: 'Verification', detail: 'Email codes, links, onboarding', group: 'Workflows' },
    { id: 'authentication', label: 'Authentication', detail: 'Sign in, validate, change password', group: 'Workflows' }
  ];

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
  let controlSection: ControlSection = 'overview';
  let inspectedProfile: UserProfile | null = null;
  let inspectedEmailContacts: AccountEmailContact[] = [];
  let verificationReason = 'administrator_review';
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

  // Application context for the workflow sections. Loaded once; the choice survives section changes.
  let workflowApplications: IdentityWorkflowApplication[] = [];
  let workflowApplicationId = '';
  let workflowResource = '';
  let workflowSettings: IdentityWorkflowSettings | null = null;
  let workflowLoaded = false;

  $: if (error) { showError(error, 'Identity operation failed'); error = ''; }

  const minimumPasswordLength = 9;
  const maximumPasswordLength = 1024;
  const pageSizes = [10, 20, 30, 40, 50];

  const statuses: IdentityStatus[] = [RecordStatus.Pending, RecordStatus.Active, RecordStatus.Locked, RecordStatus.Suspended, RecordStatus.Retired];

  function userDialogOpen() {
    return showCreate || showImport || showReset || inspectedUser !== null;
  }

  function openCreateDialog() { error = ''; showCreate = true; }
  function closeCreateDialog() { error = ''; showCreate = false; }
  function openImportDialog() { error = ''; importResult = null; showImport = true; }
  function closeImportDialog() { error = ''; showImport = false; }
  function openResetDialog() { error = ''; resetResult = null; showReset = true; }
  function closeResetDialog() { error = ''; showReset = false; }

  // Account pages have their own URL so they can open in a new browser tab:
  //   #/users                       directory
  //   #/users/<userId>[/<section>]  one account, optionally on a section
  const accountRoute = /^#\/users\/([0-9a-f-]{32,36})(?:\/([a-z-]+))?\/?$/i;
  function accountHref(user: UserIdentity, section: ControlSection = 'overview') {
    return `#/users/${user.userId}${section === 'overview' ? '' : `/${section}`}`;
  }
  function isSection(value: string | undefined): value is ControlSection {
    return sections.some(item => item.id === value);
  }
  function syncHash(section: ControlSection) {
    const next = inspectedUser ? accountHref(inspectedUser, section) : '#/users';
    if (window.location.hash !== next) history.replaceState(null, '', next);
  }
  async function openFromHash() {
    const match = accountRoute.exec(window.location.hash);
    if (!match) {
      if (inspectedUser) closeControl(true, false);
      else if (users.length === 0 && !loading) void load();
      return;
    }
    const [, userId, section] = match;
    if (inspectedUser?.userId.toLowerCase() === userId.toLowerCase()) {
      if (isSection(section) && section !== controlSection) selectSection(section, false);
      return;
    }
    try {
      const user = await adminApi.userAccount(userId);
      await openControl(user, isSection(section) ? section : 'overview', false);
    } catch (reason) {
      error = message(reason);
      await load();
    }
  }
  function onHashChange() { void openFromHash(); }

  onMount(() => {
    window.addEventListener('hashchange', onHashChange);
    if (accountRoute.test(window.location.hash)) void openFromHash();
    else void load();
  });
  onDestroy(() => {
    window.removeEventListener('hashchange', onHashChange);
    if (window.location.hash.startsWith('#/users')) history.replaceState(null, '', window.location.pathname + window.location.search);
  });

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
      if (inspectedUser?.userId === user.userId) closeControl(false, true);
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

  function closeControl(reload = true, updateHash = true) {
    inspectedUser = null;
    sessionUser = null;
    sessionResult = null;
    error = '';
    notice = '';
    if (updateHash) syncHash('overview');
    if (reload) void load(page);
  }

  function selectSection(section: ControlSection, updateHash = true) {
    controlSection = section;
    if (!inspectedUser) return;
    if (updateHash) syncHash(section);
    if (section === 'sessions' && sessionUser?.userId !== inspectedUser.userId) void openSessions(inspectedUser);
    if (section === 'verification' || section === 'authentication') void loadWorkflowContext();
  }

  async function loadWorkflowContext() {
    if (workflowLoaded) return;
    try {
      const [applications, policy] = await Promise.all([adminApi.workflowApplications(1), adminApi.workflowSettings()]);
      workflowApplications = applications.applications;
      workflowSettings = policy;
      if (!workflowApplicationId) {
        const candidate = workflowApplications.find(item => item.status === RecordStatus.Active && item.resources.length > 0);
        if (candidate) {
          workflowApplicationId = candidate.applicationId;
          workflowResource = adminApi.extended ? candidate.resources[0] ?? '' : 'haley.identity';
        }
      }
      workflowLoaded = true;
    } catch (reason) {
      error = message(reason);
    }
  }

  async function openControl(user: UserIdentity, section: ControlSection = 'overview', updateHash = true) {
    inspectedUser = user;
    controlSection = section;
    if (updateHash) syncHash(section);
    targetStatus = user.status === RecordStatus.Active ? RecordStatus.Suspended : RecordStatus.Active;
    reasonCode = 'superadmin_change';
    inspectedProfile = null;
    inspectedEmailContacts = [];
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
    window.scrollTo({ top: 0 });
    void loadWorkflowContext();
    if (section === 'sessions') void openSessions(user);
    try {
      const [profile, mfa, attempts, contacts, origins, federation, challenges, grants, policies, mfaOverrides, protectionPolicy, emailContacts] = await Promise.all([
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
        adminApi.loginProtectionPolicy(),
        adminApi.userEmailContacts(user.userId)
      ]);
      if (inspectedUser?.userId !== user.userId) return;
      inspectedProfile = profile;
      inspectedEmailContacts = emailContacts;
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

  function unusedRetiredMfaMethods(): MfaMethod[] {
    return inspectedMfa.filter(method => method.status === RecordStatus.Retired && !method.verifiedAt && !method.lastUsedAt);
  }

  async function pruneUnusedMfaMethods() {
    const user = inspectedUser;
    const count = unusedRetiredMfaMethods().length;
    if (!user || !count || !await requestConfirmation({
      title: 'Prune unused authenticators?',
      message: `Permanently remove unused retired authenticators for ${user.displayName}. Only methods that were never confirmed or used are eligible. This cannot be undone.`,
      confirmLabel: 'Prune unused',
      tone: 'danger'
    })) return;
    saving = true; error = '';
    try {
      const removed = await adminApi.pruneUnusedUserMfaMethods(user.userId);
      const methods = await adminApi.userMfa(user.userId);
      if (inspectedUser?.userId === user.userId) inspectedMfa = methods;
      notice = removed ? `Pruned ${removed} unused retired authenticator${removed === 1 ? '' : 's'}.`
        : 'No unused retired authenticators could be pruned. Methods referenced by another enrollment are retained.';
    } catch (reason) { error = message(reason); }
    finally { saving = false; }
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

  async function refreshEmailContacts() {
    const userId = inspectedUser?.userId;
    if (!userId) return;
    try {
      const contacts = await adminApi.userEmailContacts(userId);
      if (inspectedUser?.userId === userId) inspectedEmailContacts = contacts;
    } catch (reason) { if (inspectedUser?.userId === userId) error = message(reason); }
  }

  async function setEmailVerification(contact: AccountEmailContact, isVerified: boolean) {
    if (!inspectedUser || !verificationReason.trim()) return;
    const user = inspectedUser;
    const reasonCode = verificationReason.trim();
    if (!await requestConfirmation({
      title: isVerified ? 'Break-glass verify this email?' : 'Mark this email unverified?',
      message: isVerified
        ? `${contact.email} will be marked verified and recovery enabled for ${user.displayName}, without a code or link. Confirm ownership independently before proceeding. Account status is unchanged. Reason: ${reasonCode}.`
        : `${contact.email} will become unverified for ${user.displayName}. Email recovery will be disabled and outstanding email challenges and grants invalidated. Account status is unchanged. Reason: ${reasonCode}.`,
      confirmLabel: isVerified ? 'Break-glass verify' : 'Mark unverified', tone: 'danger'
    })) return;
    saving = true; error = '';
    try {
      await adminApi.setEmailVerification(user.userId, contact.contactId, isVerified, reasonCode);
      await openControl(user, 'verification');
      notice = isVerified ? 'Email verified by administrator. Recovery enabled.' : 'Email marked unverified. Outstanding email proofs invalidated.';
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
    return reason instanceof ApiError ? reason.message : reason instanceof Error ? reason.message : 'The identity service is unavailable.';
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

{#if inspectedUser}
  <section class="page user-page">
    <header class="page-header user-page-header">
      <div class="user-page-title">
        <button type="button" class="back-link" onclick={() => closeControl()}>← Back to accounts</button>
        <div class="identity-cell user-identity">
          <span>{inspectedUser.displayName.slice(0, 1).toUpperCase()}</span>
          <div>
            <h1>{inspectedUser.displayName}</h1>
            <p class="user-subline">
              <span class="status-pill {statusClass(inspectedUser.status)}">{statusLabel(inspectedUser.status)}</span>
              {#if inspectedUser.passwordChangeRequired}<span class="status-pill pending">Password change required</span>{/if}
              {#if inspectedUser.username}<button type="button" class="copy-link" class:copied={copiedIdentityValue === 'page:username'} title="Copy username" onclick={() => void copyIdentityValue('page:username', inspectedUser!.username!)}>{copiedIdentityValue === 'page:username' ? 'Copied' : inspectedUser.username}</button>{:else}<span>No username</span>{/if}
              <span class="faint">·</span>
              <button type="button" class="copy-link" class:copied={copiedIdentityValue === 'page:id'} title="Copy user ID" onclick={() => void copyIdentityValue('page:id', inspectedUser!.userId)}>{copiedIdentityValue === 'page:id' ? 'Copied' : inspectedUser.userId}</button>
            </p>
          </div>
        </div>
      </div>
      <div class="page-actions">
        {#if inspectedUser.status === RecordStatus.Locked}<button class="quiet danger-text" disabled={saving} onclick={() => void releaseLoginProtection()}>Release lock</button>{/if}
        {#if adminApi.extended}<button class="quiet" onclick={() => onAccess(inspectedUser!.userId, inspectedUser!.displayName)}>Access</button>{/if}
        <button class="quiet" onclick={resetPasswordForInspectedUser}>Reset password</button>
      </div>
    </header>

    {#if notice}<div class="notice success" role="status"><strong>Completed</strong><span>{notice}</span><button aria-label="Dismiss" onclick={() => notice = ''}>×</button></div>{/if}

    <div class="user-layout">
      <nav class="user-rail" aria-label="Account sections">
        {#each ['Account', 'Workflows'] as group}
          <small class="user-rail-label">{group}</small>
          {#each sections.filter(item => item.group === group) as item}
            <button class:active={controlSection === item.id} aria-current={controlSection === item.id ? 'page' : undefined} onclick={() => selectSection(item.id)}><span>{item.label}</span><small>{item.detail}</small></button>
          {/each}
        {/each}
      </nav>

      <div class="user-content">
        {#if inspectorLoading}
          <div class="panel empty-state">Loading account…</div>
        {:else if controlSection === 'overview'}
          <article class="panel compact control-panel">
            <div class="panel-heading"><div><p class="eyebrow">Account</p><h3>{inspectedProfile?.preferredName ?? inspectedUser.displayName}</h3></div><small>Created {date(inspectedUser.createdAt)}</small></div>
            <dl class="detail-list">
              <div><dt>Username</dt><dd>{inspectedUser.username ?? 'Not assigned'}</dd></div>
              <div><dt>User ID</dt><dd><code>{inspectedUser.userId}</code></dd></div>
              <div><dt>Status</dt><dd><span class="status-pill {statusClass(inspectedUser.status)}">{statusLabel(inspectedUser.status)}</span></dd></div>
              <div><dt>Email verification</dt><dd>{#each inspectedEmailContacts as contact}<div><strong>{contact.email}</strong> · <span class="status-pill {contact.isVerified ? 'active' : 'pending'}">{contact.isVerified ? 'Verified' : 'Unverified'}</span>{#if contact.isVerified && !contact.recoveryEnabled}<small>Recovery disabled</small>{/if}</div>{:else}No recorded email contact{/each}</dd></div>
              <div><dt>Password state</dt><dd>{inspectedUser.passwordChangeRequired ? 'Change required on next sign-in' : 'Current'}</dd></div>
              <div><dt>Last authentication</dt><dd>{date(inspectedUser.lastAuthenticatedAt)}</dd></div>
              <div><dt>Authenticators</dt><dd>{currentMfaMethods().length} current · {inspectedMfa.length - currentMfaMethods().length} retired</dd></div>
              <div><dt>Profile modified</dt><dd>{date(inspectedProfile?.modifiedAt ?? null)}</dd></div>
            </dl>
          </article>
          <IdentityWorkflows view="profile" bind:account={inspectedUser} applications={workflowApplications} bind:applicationId={workflowApplicationId} bind:resource={workflowResource} settings={workflowSettings} />

        {:else if controlSection === 'security'}
          <article class="panel compact control-panel">
            <div class="panel-heading"><div><p class="eyebrow">MFA posture</p><h3>{currentMfaMethods().length} current method{currentMfaMethods().length === 1 ? '' : 's'}</h3></div><button class="quiet" disabled={saving} onclick={() => void beginTotpEnrollment()}>{currentMfaMethods().some(method => method.kind === 'Totp' && method.status === RecordStatus.Pending) ? 'Restart enrollment' : 'Enroll authenticator'}</button></div>
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
            {#if inspectedMfa.length > currentMfaMethods().length}
              <div class="panel-heading">
                <p class="form-note">{inspectedMfa.length - currentMfaMethods().length} historical method(s) are hidden here. {unusedRetiredMfaMethods().length} retired method(s) were never confirmed or used.</p>
                <button class="quiet danger-text" disabled={saving || !unusedRetiredMfaMethods().length} onclick={() => void pruneUnusedMfaMethods()}>Prune unused</button>
              </div>
            {/if}
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
          <IdentityWorkflows view="recovery" bind:account={inspectedUser} applications={workflowApplications} bind:applicationId={workflowApplicationId} bind:resource={workflowResource} settings={workflowSettings} />

        {:else if controlSection === 'sessions'}
          <article class="panel compact control-panel">
            <div class="panel-heading"><div><p class="eyebrow">Sessions</p><h3>{sessionView === RecordStatus.Active ? 'Active sessions' : 'All sessions'}</h3></div>
              <div class="session-tabs" role="tablist" aria-label="Session view">
                <button class:active={sessionView === RecordStatus.Active} role="tab" aria-selected={sessionView === RecordStatus.Active} onclick={() => void changeSessionView(RecordStatus.Active)}>Active</button>
                <button class:active={sessionView === 'all'} role="tab" aria-selected={sessionView === 'all'} onclick={() => void changeSessionView('all')}>All</button>
              </div>
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
                    <div><strong>{statusLabel(sessionStatus(session))}{session.resource ? ` · ${session.resource}` : ''}</strong><small>{session.sessionId} · client {session.applicationId ?? session.clientId ?? 'not recorded'} · last seen {date(session.lastSeenAt)} · expires {date(session.expiresAt)}{session.endedAt ? ` · ended ${date(session.endedAt)}` : ''}</small></div>
                    {#if isActiveSession(session)}<button class="danger-text" onclick={() => revoke(session.sessionId, inspectedUser!.userId)}>Revoke</button>{/if}
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

        {:else if controlSection === 'verification'}
          {#if !adminApi.extended}
            <article class="panel compact control-panel">
              <div class="panel-heading"><div><p class="eyebrow">Administrative verification</p><h3>Email ownership</h3></div></div>
              <p class="form-note danger-note">Break-glass verify confirms ownership without a code or link and enables email recovery. Mark unverified withdraws that confirmation. Both actions record the administrator's reason and leave account status unchanged.</p>
              <label>Reason code<input bind:value={verificationReason} required maxlength="100" disabled={saving} /></label>
              <div class="security-list">
                {#each inspectedEmailContacts as contact}
                  <div><span class="status-pill {contact.isVerified ? 'active' : 'pending'}">{contact.isVerified ? 'Verified' : 'Unverified'}</span><div><strong>{contact.email}</strong><small>{contact.isVerified ? `Verified ${date(contact.verifiedAt)} · recovery ${contact.recoveryEnabled ? 'on' : 'off'}` : 'Mailbox ownership not confirmed'}</small></div>
                    <button class="danger-text" disabled={saving || !verificationReason.trim()} onclick={() => void setEmailVerification(contact, true)}>Break-glass verify</button>
                    {#if contact.isVerified}<button class="danger-text" disabled={saving || !verificationReason.trim()} onclick={() => void setEmailVerification(contact, false)}>Mark unverified</button>{/if}
                  </div>
                {:else}<p class="muted control-empty">No email contact is recorded for this identity.</p>{/each}
              </div>
            </article>
          {/if}
          <IdentityWorkflows view="verification" bind:account={inspectedUser} applications={workflowApplications} bind:applicationId={workflowApplicationId} bind:resource={workflowResource} settings={workflowSettings} onVerificationChanged={refreshEmailContacts} />
          {#if adminApi.extended}
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
            <article class="panel table-panel control-panel">
              <div class="panel-heading"><div><p class="eyebrow">Lifecycle evidence</p><h3>Contacts, origin, federation, and verification</h3></div><small>{inspectedEvidence.length} recent records</small></div>
              <div class="table-wrap"><table><thead><tr><th>Area</th><th>Type</th><th>Status</th><th>Context</th><th>Observed</th></tr></thead><tbody>{#each inspectedEvidence as record}<tr><td>{record.area}</td><td>{record.type}</td><td><span class="status-pill {record.status === RecordStatus.Active || record.status === RecordStatus.Verified || record.status === OperationalStatus.Linked || record.status === OperationalStatus.Recorded ? 'active' : record.status === RecordStatus.Pending ? 'pending' : ''}">{operationalStatusLabel(record.status)}</span></td><td>{record.provider ?? record.detail ?? '-'}{#if record.attempts !== null}<small>{record.attempts} attempts</small>{/if}</td><td>{date(record.occurredAt)}</td></tr>{:else}<tr><td colspan="5"><div class="empty-state">No lifecycle evidence is recorded.</div></td></tr>{/each}</tbody></table></div>
            </article>
          {/if}

        {:else if controlSection === 'authentication'}
          <IdentityWorkflows view="authentication" bind:account={inspectedUser} applications={workflowApplications} bind:applicationId={workflowApplicationId} bind:resource={workflowResource} settings={workflowSettings} />

        {:else}
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
        {/if}
      </div>
    </div>
  </section>
{:else}
  <section class="page">
    <header class="page-header">
      <div><p class="eyebrow">Identity authority</p><h1>Accounts</h1></div>
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
      <div class="panel-heading"><div><p class="eyebrow">Directory</p><h3>Identity records</h3></div><small>{pageSize} records per page · open an account to manage it in one place</small></div>
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
                  <td><div class="identity-primary-cell"><input type="checkbox" aria-label={`Select ${user.displayName}`} checked={selectedUserIds.has(user.userId)} onchange={() => toggleSelection(user.userId)} /><div class="identity-cell"><span>{user.displayName.slice(0, 1).toUpperCase()}</span><div><a class="copy-link identity-copy-line identity-name" href={accountHref(user)} target="_blank" rel="noopener" title={`Open ${user.displayName} in a new tab`}>{user.displayName}</a></div></div></div></td>
                  <td><span class="status-pill {statusClass(user.status)}">{statusLabel(user.status)}</span>{#if user.passwordChangeRequired}<small class="password-flag">Password change required</small>{/if}</td>
                  <td title={date(user.createdAt)}>{date(user.createdAt)}</td>
                </tr>
                <tr class="identity-secondary-row" class:selected-row={selectedUserIds.has(user.userId)}>
                  <td colspan="3"><div class="identity-secondary-content"><div class="identity-meta-lines">{#if user.username}<button type="button" class="copy-link identity-copy-line" class:copied={copiedIdentityValue === `username:${user.userId}`} title={`Copy ${user.username}`} aria-label={`Copy email or username ${user.username}`} onclick={() => void copyIdentityValue(`username:${user.userId}`, user.username!)}>{copiedIdentityValue === `username:${user.userId}` ? 'Copied' : user.username}</button>{:else}<span class="identity-copy-line">No username</span>{/if}<button type="button" class="copy-link identity-copy-line" class:copied={copiedIdentityValue === `id:${user.userId}`} title={`Copy ${user.userId}`} aria-label={`Copy user ID ${user.userId}`} onclick={() => void copyIdentityValue(`id:${user.userId}`, user.userId)}>{copiedIdentityValue === `id:${user.userId}` ? 'Copied' : user.userId}</button></div><div class="row-actions"><a class="row-link" href={accountHref(user, 'sessions')} target="_blank" rel="noopener" title="Open sessions in a new tab">Sessions</a>{#if adminApi.extended}<button onclick={() => onAccess(user.userId, user.displayName)}>Access</button>{/if}<a class="row-link primary" href={accountHref(user)} target="_blank" rel="noopener" title="Open this account in a new tab">Open ↗</a></div></div></td>
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

<style>
  /* Directory links that open an account page in a new tab, styled like the row buttons. */
  .row-actions .row-link { display: inline-flex; align-items: center; gap: 4px; padding: 6px 10px; border: 1px solid var(--line-strong); border-radius: 7px; background: var(--surface); color: var(--text-soft); font-size: 12.5px; font-weight: 600; text-decoration: none; white-space: nowrap; }
  .row-actions .row-link:hover { background: var(--surface-2); }
  .row-actions .row-link.primary { color: #fff; background: var(--mint-dark); border-color: var(--mint-dark); box-shadow: 0 1px 2px rgba(55, 48, 163, .14); }
  .row-actions .row-link.primary:hover { background: var(--mint); border-color: var(--mint); }
  a.identity-name { text-decoration: none; }
  /* Account page: full-width replacement for the old control popup. */
  .user-page-header { align-items: center; margin-bottom: 18px; }
  .user-page-title { min-width: 0; }
  .back-link { display: inline-flex; align-items: center; gap: 6px; margin: 0 0 10px; padding: 0; border: 0; background: none; color: var(--mint-dark); font-size: 12.5px; font-weight: 650; }
  .back-link:hover { text-decoration: underline; }
  .user-identity { gap: 14px; }
  .user-identity > span { width: 46px; height: 46px; border-radius: 12px; font-size: 16px; }
  .user-identity h1 { margin: 0; font-size: clamp(22px, 2.6vw, 28px); line-height: 1.15; }
  .user-subline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 5px 0 0; color: var(--muted); font-size: 12.5px; }
  .user-subline .copy-link { max-width: 100%; overflow: hidden; color: var(--muted); font-family: var(--font-mono); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
  .user-subline .copy-link:hover, .user-subline .copy-link.copied { color: var(--mint-dark); }
  .user-subline .faint { color: var(--line-strong); }
  .user-subline .status-pill { margin: 0; }
  .user-layout { display: grid; grid-template-columns: 224px minmax(0, 1fr); gap: 18px; align-items: start; }
  .user-rail { position: sticky; top: 20px; display: grid; gap: 3px; padding: 8px; border: 1px solid var(--line); border-radius: 14px; background: var(--surface); box-shadow: var(--shadow-sm); }
  .user-rail-label { padding: 10px 10px 4px; color: var(--faint); font-size: 10.5px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
  .user-rail-label:first-child { padding-top: 4px; }
  .user-rail button { display: block; width: 100%; min-height: 0; padding: 9px 11px; border: 1px solid transparent; border-radius: 10px; background: transparent; color: var(--text-soft); text-align: left; }
  .user-rail button:hover { background: var(--surface-2); color: var(--text); }
  .user-rail button.active { background: var(--accent-soft); border-color: var(--accent-soft-line); color: var(--mint-dark); }
  .user-rail button span { display: block; font-size: 13px; font-weight: 650; }
  .user-rail button small { display: block; margin-top: 1px; color: var(--muted); font-size: 11px; }
  .user-rail button.active small { color: var(--mint-dark); opacity: .75; }
  .user-content { min-width: 0; display: grid; gap: 14px; align-content: start; }
  .user-content :global(.control-panel) { margin: 0; box-shadow: var(--shadow-sm); }
  .user-content :global(.notice) { margin: 0; }
  .user-content .detail-list dd code { color: var(--muted); font-size: 12px; }
  .user-content .session-tabs { margin: 0; }
  .user-content .panel.empty-state { padding: 48px 20px; }
  @media (max-width: 980px) {
    .user-layout { grid-template-columns: 1fr; }
    .user-rail { position: static; display: flex; gap: 4px; overflow-x: auto; }
    .user-rail-label { display: none; }
    .user-rail button { flex: 0 0 auto; width: auto; }
    .user-rail button small { display: none; }
  }
</style>
