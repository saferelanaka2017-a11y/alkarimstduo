/**
 * Security Rules Adversarial Verification Suite (Phase 0 TDD)
 * Validates the Dirty Dozen payloads against AlKarim Firestore rules invariants.
 */

export const dirtyDozenPayloads = [
  {
    name: 'Shadow Field Injection on App Create',
    path: '/apps/app_shadow',
    operation: 'create',
    payload: { id: 'app_shadow', isFeaturedAdmin: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Owner Spoofing on App Create',
    path: '/apps/app_spoof',
    operation: 'create',
    payload: { id: 'app_spoof', ownerId: 'victim_uid' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Privilege Escalation on User Profile',
    path: '/users/attacker_uid',
    operation: 'create',
    payload: { uid: 'attacker_uid', role: 'admin' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Cross-User PII Read',
    path: '/users/victim_uid/private/security',
    operation: 'get',
    payload: null,
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Unverified Email Write',
    path: '/apps/app_unverified',
    operation: 'create',
    auth: { uid: 'u1', email_verified: false },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Orphaned Release Creation',
    path: '/apps/missing_app/releases/r1',
    operation: 'create',
    payload: { id: 'r1', appId: 'missing_app' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Cross-Owner Release Injection',
    path: '/apps/victim_app/releases/r_evil',
    operation: 'create',
    payload: { id: 'r_evil', appId: 'victim_app' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'ID Poisoning',
    path: '/apps/' + 'a'.repeat(200),
    operation: 'create',
    payload: {},
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Client Timestamp Forgery',
    path: '/apps/app_time',
    operation: 'create',
    payload: { createdAt: '2020-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Download Counter Tampering',
    path: '/apps/public_app',
    operation: 'update',
    payload: { downloadsCount: 999999 },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'Private App Scraping via List',
    path: '/apps',
    operation: 'list',
    query: { visibility: 'private' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: 'API Key Secret Mutation',
    path: '/api_keys/key_1',
    operation: 'update',
    payload: { keyHash: 'forged_hash' },
    expected: 'PERMISSION_DENIED',
  },
];
