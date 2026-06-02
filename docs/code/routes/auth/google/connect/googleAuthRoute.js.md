> Generated without selected-node repository context.

# Quick File Audit
**Path:** `routes/auth/google/connect/googleAuthRoute.js`
**Confidence:** medium

The route implements a robust OAuth flow with necessary security headers and rate limiting. However, the business logic for user recovery and account linking is highly nested and prone to race conditions. Refactoring the user resolution logic into a single atomic transaction and moving non-critical side effects (like avatar uploads) to asynchronous tasks would significantly improve performance and reliability.

## Strengths
- Effective use of rate limiting to mitigate brute-force and DoS attempts on the OAuth endpoint.
- Comprehensive logging strategy for both success and failure states, aiding in auditability.
- Clear separation of concerns by delegating complex logic to helper functions.

## Issues
- [Lines 105-107] Potential race condition: `userByEmail.isDeleted` check followed by an update is not atomic. If multiple requests arrive simultaneously, it could lead to inconsistent state.
- [Lines 126-131] Logic error: `userOAuth` check is performed after `userByEmail` check, but the `userOAuth` object contains the `user` relation. If `userByEmail` is null, `userOAuth.user` might be accessed safely, but the logic flow is fragmented.
- [Lines 156-170] Side-effect risk: `uploadAvatarAndUpdateUser` is called after user creation but before final session validation, potentially performing unnecessary I/O if the session creation fails later.

## Suggestions
- [Lines 105-107] Use a Prisma transaction to ensure the `isDeleted` check and subsequent update are atomic.
- [Lines 136-140] Consolidate user creation and avatar synchronization logic to reduce database round-trips.
- [Lines 156-170] Move avatar processing to a background job or post-authentication hook to reduce request latency.
- [Lines 100-120] Refactor the nested if-else blocks into a guard-clause pattern to reduce cyclomatic complexity.
- [Lines 180-181] Validate `deviceId` before performing expensive database operations or external API calls.