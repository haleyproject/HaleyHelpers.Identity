import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/shared/lib/statuses.ts', import.meta.url), 'utf8');
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext }
});
const statuses = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);

for (const [label, className, known, expectedLabel, expectedClass, unknownClass] of [
  ['statusLabel', 'statusClass', statuses.RecordStatus.Active, 'Active', 'active', 'unknown'],
  ['operationalStatusLabel', 'operationalStatusClass', statuses.OperationalStatus.PasswordChangeRequired, 'Password Change Required', 'password_change_required', 'unknown'],
  ['certificateStatusLabel', 'certificateStatusClass', statuses.CertificateStatus.NotYetValid, 'Not Yet Valid', 'not-yet-valid', 'invalid']
]) {
  test(`${label} and ${className} format numeric wire values`, () => {
    assert.equal(statuses[label](known), expectedLabel);
    assert.equal(statuses[className](known), expectedClass);
    assert.equal(statuses[label](0), 'Unknown (0)');
    assert.equal(statuses[className](0), unknownClass);
  });

  test(`${label} and ${className} do not crash on malformed JSON status values`, () => {
    for (const value of ['Active', 'Pending', 'PasswordChangeRequired', 'NotYetValid', '2', null, {}, []]) {
      assert.match(statuses[label](value), /^Unknown \(/);
      assert.equal(statuses[className](value), unknownClass);
    }
  });
}

test('empty lifecycle and operational filters still mean all statuses', () => {
  assert.equal(statuses.statusLabel(''), 'All statuses');
  assert.equal(statuses.operationalStatusLabel(''), 'All statuses');
});
