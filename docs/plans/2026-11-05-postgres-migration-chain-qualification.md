# OmniPanel v2 — apply the published PostgreSQL migrations in grant integration tests

**Target:** unified PR #2. **Finding addressed:** reduce the production-shape blind spot where grant tests fabricated only `admins`, `admin_sessions` and `nodes` instead of applying migrations 0001–0007.

## Scope

- Fix the initial migration's invalid partial-unique-constraint syntax by expressing the active-principal rule as a PostgreSQL partial unique index, matching `src/db/schema.ts`.
- Run the admin-grant PostgreSQL integration against an isolated, random schema and apply the entire ordered migration chain 0001 through 0007 before seeding real-schema rows and exercising grant/step-up/redeem behavior.
- Ensure workflow path filters run when 0001/0002 change.

## Acceptance and limits

- [ ] PostgreSQL 17.6 CI applies every migration in order, executes the grant/step-up/redemption suite against the resulting schema, and drops the isolated schema.
- [ ] Existing race, vet, gofmt, TypeScript and local runtime checks remain green.

This provides schema-shape and service-query integration coverage for this disposable test setup. It does not establish production database roles/privileges, migration rollback/PITR, least-privilege deployment, issuer custody, or production qualification. The trusted-TOTP writer and separate database-role boundary remain open security work.
