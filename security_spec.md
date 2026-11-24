# AlKarim Security Specification (Phase 0 TDD)

## 1. Data Invariants
1. **Owner & Identity Integrity**: Every `SoftwareApp`, `AppRelease`, `ApiKeyRecord`, and `PeriodicReport` MUST bind `ownerId == request.auth.uid` on creation and preserve `ownerId` immutably on updates.
2. **PII Isolation**: User email, auth provider, and 2FA `totpSecret` live strictly under `/users/{userId}/private/security`, readable and writable only by `request.auth.uid == userId`.
3. **Master Gate Relational Sync**: Every `/apps/{appId}/releases/{releaseId}` write MUST verify parent `/apps/{appId}` exists, is owned by `request.auth.uid`, and matches `visibility`.
4. **Report Integrity**: Every `/reports/{reportId}` creation MUST verify the referenced `appId` exists and belongs to `request.auth.uid`.
5. **Verified Write Enforcement**: All write mutations require `request.auth.token.email_verified == true`.
6. **Temporal Integrity**: `createdAt` and `updatedAt` MUST equal `request.time` on creation, and `createdAt` is immutable on update.
7. **Strict Schema & Bounds**: All strings, lists, numbers, and document IDs are strictly type-checked and bounded; shadow/unknown fields are rejected via `hasOnly`.

## 2. The Dirty Dozen Adversarial Payloads
1. **Shadow Field Injection on App Create**: `{ id: "app1", ..., isFeaturedAdmin: true }` -> `PERMISSION_DENIED` (`hasOnly` rejects unknown key).
2. **Owner Spoofing on App Create**: `{ id: "app1", ownerId: "victim_uid", ... }` -> `PERMISSION_DENIED` (`ownerId != request.auth.uid`).
3. **Privilege Escalation on User Profile**: `{ uid: "u1", role: "admin", ... }` -> `PERMISSION_DENIED` (`role` must equal `'developer'` on create and is immutable on update).
4. **Cross-User PII Read**: Authenticated attacker reads `/users/victim_uid/private/security` -> `PERMISSION_DENIED`.
5. **Unverified Email Write**: Authenticated user with `email_verified: false` creates `/apps/app1` -> `PERMISSION_DENIED`.
6. **Orphaned Release Creation**: Attacker creates `/apps/nonexistent_app/releases/r1` -> `PERMISSION_DENIED` (`exists` Master Gate fails).
7. **Cross-Owner Release Injection**: Attacker creates release under victim's `/apps/victim_app/releases/r1` -> `PERMISSION_DENIED`.
8. **ID Poisoning**: Document ID of 200 chars or containing `../$bad` -> `PERMISSION_DENIED` (`isValidId` rejects).
9. **Client Timestamp Forgery**: `{ ..., createdAt: "2020-01-01T00:00:00Z" }` -> `PERMISSION_DENIED` (`createdAt == request.time` fails).
10. **Download Counter Tampering**: Non-owner sets `downloadsCount: 999999` on public app -> `PERMISSION_DENIED` (`downloadsCount == existing().downloadsCount + 1` required).
11. **Private App Scraping via List**: Non-owner queries `apps` where `visibility == 'private'` -> `PERMISSION_DENIED`.
12. **API Key Secret Mutation**: Owner tries to mutate `keyHash` or `prefix` on existing `/api_keys/{keyId}` -> `PERMISSION_DENIED` (`affectedKeys().hasOnly(['label', 'status', 'updatedAt'])`).
