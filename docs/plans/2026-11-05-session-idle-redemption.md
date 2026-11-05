# OmniPanel v2 — revalidate administrator idle lifetime at enrollment redemption

**Target:** unified PR #2. **Scope:** close the session-idle authorization gap in `ApprovedSQLStore`; no issuer deployment or schema change.

## Security invariant

A grant remains redeemable only while its issuing administrator session is live under the same database-clocked lifetime policy used when issuing it: session timestamps are not future-dated, absolute age is under 12 hours, idle age is under 2 hours, and `expires_at` is in the future. Apply this invariant to both preliminary token lookup and the locked transaction query used by certificate commit.

## Regression coverage

Issue a valid grant, age its still-unexpired admin session beyond the two-hour idle limit, and prove both lookup and commit reject it. Confirm rejection does not consume the enrollment token; restore `last_seen_at` and prove the valid grant can still be committed. Run this against the disposable PostgreSQL integration service on the final PR head.

## Boundaries

This fixes redemption-time revalidation in the library adapter. It does not provide protected TOTP secret custody, trusted database-role separation, production-shaped full migration qualification, a deployed issuer, or production acceptance. All release gates remain BLOCKED.
