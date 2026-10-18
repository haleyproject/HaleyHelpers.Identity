'use strict';
(() => {
  const element = id => document.getElementById(id);
  const error = message => { element('error').textContent = message; element('error').hidden = false; };
  let link;
  try {
    const encoded = new URLSearchParams(window.location.hash.slice(1)).get('proof');
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    if (!encoded || encoded.length > 12000) throw new Error('This link is incomplete. Open the original link or request a new one.');
    link = JSON.parse(encoded);
    link.applicationId ??= link.clientId;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(link.applicationId ?? '') ||
        !/^[0-9a-f-]{36}$/i.test(link.challengeId ?? '') || typeof link.resource !== 'string' || !link.resource || link.resource.length > 200 ||
        ![1,2,4,8].includes(link.purpose) || ![1,2].includes(link.proofKind) || link.context != null && (typeof link.context !== 'string' || link.context.length > 1000) ||
        !Number.isFinite(Date.parse(link.expiresAt))) throw new Error('This verification link is invalid. Request a new link.');
    if (Date.parse(link.expiresAt) <= Date.now()) throw new Error('This verification link has expired. Request a new link.');
    if (link.proofKind === 1 && (typeof link.verifier !== 'string' || !link.verifier || link.verifier.length > 1000)) throw new Error('The one-time proof is missing.');
    const headings = {1:'Verify your email',2:'Activate your account',4:'Reset your password',8:'Complete sign-in'};
    element('heading').textContent = headings[link.purpose]; document.title = headings[link.purpose];
    element('description').textContent = `For ${link.email ?? 'your account'}. Expires ${new Date(link.expiresAt).toLocaleString()}.`;
    element('code-field').hidden = link.proofKind !== 2; element('code').required = link.proofKind === 2;
    const passwordRequired = link.purpose === 4 || link.purpose === 2 && link.requiresPassword === true;
    element('password-fields').hidden = !passwordRequired; element('password').required = passwordRequired; element('confirmation').required = passwordRequired;
    element('mfa-fields').hidden = link.purpose !== 8;
    element('verification').hidden = false;
  } catch (reason) { element('description').textContent = ''; error(reason.message ?? 'The link could not be opened.'); return; }
  element('verification').addEventListener('submit', async event => {
    event.preventDefault(); element('error').hidden = true;
    const password = element('password').value;
    if (password !== element('confirmation').value) { error('The passwords do not match.'); return; }
    const verifier = link.proofKind === 1 ? link.verifier : element('code').value.trim();
    if (!verifier) { error('Enter the verification code.'); return; }
    const button = element('submit'); button.disabled = true; button.textContent = 'Verifying...';
    try {
      const submission = {challengeId:link.challengeId,purpose:link.purpose,proofKind:link.proofKind,context:link.context ?? null,verifier};
      if (password) submission.newPassword = password;
      if (link.purpose === 8 && element('mfa-code').value.trim()) { submission.mfaKind = element('mfa-kind').value; submission.mfaCode = element('mfa-code').value.trim(); }
      const url = `./${encodeURIComponent(link.applicationId)}/${encodeURIComponent(link.resource)}/completion`;
      const response = await fetch(url,{method:'POST',credentials:'omit',cache:'no-store',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify(submission)});
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail ?? body.title ?? 'Verification could not be completed.');
      element('verification').hidden = true; element('description').textContent = '';
      element('success').textContent = body.purpose === 2 || body.purpose === 'Onboarding' ? 'Your email is verified and your account is active. You can return to your application.' :
        link.purpose === 4 ? 'Your password has been changed. You can return to your application.' : link.purpose === 8 ? 'Your sign-in proof was accepted. Return to your application to continue.' :
        'Your email is verified. You can close this page and return to your application.';
      element('success').hidden = false; link.verifier = undefined; element('code').value = '';
    } catch (reason) { error(reason.message ?? 'Verification failed.'); }
    finally { element('password').value = ''; element('confirmation').value = ''; element('mfa-code').value = ''; button.disabled = false; button.textContent = 'Confirm verification'; }
  });
})();
