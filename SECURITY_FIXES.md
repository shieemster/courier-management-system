# Security Fixes Applied — Part 2

This document is the engineering record of every fix applied to the forked
`courier-management-system` repo for CT123-3-3 Part 2. Use it as the source
material for the "Security Mitigation Implementation" and "Secure Coding
Techniques Implemented" sections of the report (it already has the
before/after reasoning; take screenshots of the actual diffs/files it
references).

## ⚠️ Required one-time step before you test anything

The seed data in `Database/royal_express_db.sql` stores every password as
plain text (`testuser1`, `emp1`, `12345`, ...). Login now uses
`password_verify()` against a bcrypt hash, so **existing accounts cannot log
in until you run the migration script once**:

```bash
# with Apache + MySQL running
http://localhost/courier-management-system/migrate_passwords.php
```

Then **delete `migrate_passwords.php`** (or move it outside the webroot).
It is a one-shot tool — leaving a script that rewrites every password hash
reachable over HTTP would itself be a vulnerability.

## V-01 — SQL Injection (HIGH)

- Every query in `server/inc/get.php`, `add.php`, `update.php`, `delete.php`
  was rebuilt from string concatenation to **mysqli prepared statements**
  (`mysqli_prepare` + `bind_param`). Functions still return a
  `mysqli_result` (via `->get_result()`), so no caller elsewhere in the app
  had to change.
- `server/inc/connection.php` also exposes a `$pdo` PDO handle
  (`PDO::ATTR_EMULATE_PREPARES => false`) for the report's PDO exhibit and
  for any new code going forward — see the login flow in `getLoginAdmin()`.
- **The bigger finding**: `updateDataTable()`, `deleteDataTables()`,
  `permanantDeleteDataTable()`, `dataCount()` etc. take the *table and
  column name* from `$_POST`, not just the value — you cannot bind an
  identifier as a parameter. `server/inc/table_whitelist.php` adds a strict
  allow-list every dynamic table/column is validated against before it is
  used in SQL. This was reachable **without any login** (see V-02/RBAC
  below) — effectively an unauthenticated arbitrary-table SQL injection +
  mass-assignment bug. Worth its own bullet in the report as the most
  significant finding.

## V-02 — CSRF (MEDIUM)

- `includes/csrf_helper.php`: synchroniser-token pattern
  (`generate_csrf_token()` / `validate_csrf_token()` / `require_csrf_token()`).
- A `<meta name="csrf-token">` tag is rendered on every page
  (`pages/head.php`, `Admin/pages/head.php`).
- `Admin/assets/js/include/csrf.js` — a single jQuery `ajaxPrefilter`
  attaches the token to **every** POST request automatically (works for
  both `FormData` uploads and plain-object payloads), so all ~20 existing
  AJAX call sites across `add.js` / `homejs.js` / `main.js` / `delete.js` /
  `upload.js` got covered without editing each one individually.
- `server/api.php` calls `require_csrf_token()` for every state-changing
  `function_code` (read-only lookups like `checkArea` are exempt).
- Explicit `<?php echo csrf_field(); ?>` also added to the login, register,
  contact, request, change-password and change-email `<form>` tags for a
  clean before/after screenshot.

## V-03 — Missing CSP / security headers (MEDIUM)

- `includes/security_headers.php`: CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and
  HSTS when served over HTTPS.
- Included via `includes/bootstrap.php`, which every entry page now
  `require_once`s as its literal first statement — see the RBAC section
  below for why that ordering matters.

## V-04 — Plaintext password storage (HIGH)

- `password_hash(..., PASSWORD_BCRYPT, ['cost' => 12])` on registration
  (`createCustomer`) and staff creation (`addEmployee`).
- Login (`getLoginAdmin`) and the two "confirm your current password"
  endpoints (`checkuserPassword`, `checkPasswordByName`) now fetch the
  stored hash and check it with `password_verify()` instead of comparing
  the raw password inside the SQL `WHERE` clause.
- `migrate_passwords.php` — one-time migration for the existing seed data
  (see the required step above).

## RBAC bypass (confirmed in Part 1: "/Admin/ works as Customer/Employee")

**Root cause, not just a missing check**: `pages/head.php` and
`Admin/pages/head.php` print raw `<head>` HTML as their very first byte.
The old guards (`auth.php`, `Admin/admin.php`, `Admin/checkAdmin.php`) ran
*after* that output via `header("Location: ...")` **with no `exit()`**.
Once headers are sent, `header()` fails silently in PHP — so the redirect
never happened and the protected page rendered in full regardless of role.
This is a good before/after screenshot: same `header()` call, but ordering
+ `exit()` is the actual fix.

Fix: `includes/guards.php` (`require_customer_login()`,
`require_staff_login()`, `require_super_admin()`) — each calls `exit()`
immediately after the redirect — is now invoked as the **first statement**
of every entry page, before `<!DOCTYPE html>` / before `pages/head.php` is
included. Applied to all of: `index.php`, `request.php`, `tracking.php`,
`profile.php`, `change_password.php`, `change_email.php`, and every file
under `Admin/` (`add_courier.php`, `add_request.php`, `area.php`,
`branch.php`, `courier.php`, `customer.php`, `employee.php`,
`empolyee_edit.php`, `gallery.php`, `index.php`, `login.php`, `logout.php`,
`message.php`, `price.php`, `register.php`, `settings.php`, `getbill.php`).

`area.php` / `branch.php` / `gallery.php` are restricted to the super-admin
account (`email = 'admin'`) via `require_super_admin()`, matching what the
original (broken) `checkAdmin.php` was clearly trying to do.

## IDOR (Insecure Direct Object Reference)

- **`Admin/getbill.php`** had *no session check at all* and trusted
  `?customer_id=` from the query string directly — anyone could download
  any other customer's shipment receipt (name, email, phone, address) by
  changing a number in the URL. Fixed: a customer session always uses
  `$_SESSION['customer']` (the URL parameter is ignored); staff/admin may
  still look up any customer.
- **Order cancellation** (`tracking.php`'s "Cancel" dropdown, backed by the
  generic `updateData` endpoint): the old code let any logged-in customer
  cancel *any* request by guessing `request_id`. `server/api.php` now
  checks `getRequestByIdForCustomer()` to confirm the request actually
  belongs to the session's customer before allowing the update.
- **`addRequest`**: `customer_id` is now taken from `$_SESSION['customer']`
  server-side, never trusted from the POST body.
- **Self-service password/email endpoints** (`checkPassword`, `checkEmail`,
  `checkPasswordByEmail`, and the `updateData` calls they feed into) now
  verify the target row belongs to the caller's own session before running.

## Output encoding (stored/reflected XSS hardening)

- `includes/functions.php` — `e()` wraps `htmlspecialchars(...,
  ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`.
- Applied to every place shipment/customer data (address, phone, name,
  email, tracking fields) is echoed back into HTML in `tracking.php`,
  `profile.php`, `change_password.php`, `change_email.php`, and
  `Admin/courier.php` (representative Admin listing page — the same
  pattern applies to the other Admin listing pages if you want to extend
  it for the report).

## Session hardening

`includes/session_config.php`: `httponly` + `SameSite=Strict` cookies,
`use_strict_mode`, secure cookies over HTTPS, and a 30-minute idle timeout.
Called once via `includes/bootstrap.php`.

## Files added

```
includes/session_config.php
includes/security_headers.php
includes/csrf_helper.php
includes/functions.php
includes/guards.php
includes/bootstrap.php
server/inc/table_whitelist.php
Admin/assets/js/include/csrf.js
migrate_passwords.php        (delete after running once)
sonar-project.properties
.github/workflows/sonarcloud.yml
```

## Next steps for you (need your own GitHub/SonarCloud login)

1. Run `migrate_passwords.php` once, then delete it (see top of this file).
2. Test locally in XAMPP: login as `admin`/`12345` (staff) and as
   `testuser1@royalexpress.com`/`testuser1` (customer) — passwords are
   unchanged, only their storage format changed.
3. Push this branch to your fork on GitHub.
4. Go to sonarcloud.io → "Log in with GitHub" → **+** → "Analyze new
   project" → pick your fork → "GitHub Actions" as the analysis method.
5. Edit `sonar-project.properties` in this repo: replace
   `YOUR_GITHUB_USERNAME` with the SonarCloud organization key it shows you.
6. SonarCloud will give you a `SONAR_TOKEN` — add it under your GitHub
   repo's **Settings → Secrets and variables → Actions** as `SONAR_TOKEN`.
7. Push again (or re-run the workflow from the Actions tab) — SonarCloud
   analyses the push via `.github/workflows/sonarcloud.yml` and populates
   the dashboard. Screenshot: Overview, Security tab, Issues list.
8. Re-run OWASP ZAP against the fixed app for the "after mitigation" DAST
   comparison in Part 2.
