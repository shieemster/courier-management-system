<?php
/**
 * guards.php
 * -----------
 * Centralised RBAC guards (fix for the confirmed Part 1 RBAC gap and for
 * Fix 5 / IDOR protection). Every guard calls exit() immediately after the
 * redirect header, unlike the original auth.php / admin.php / checkAdmin.php,
 * whose missing exit() (combined with output already sent by pages/head.php)
 * was the actual root cause of "/Admin/ works as Customer/Employee".
 *
 * Call a guard as the FIRST line of a page, before any include that prints
 * markup (pages/head.php, <!DOCTYPE html>, etc).
 */

function require_customer_login(string $loginUrl = 'admin/login.php'): void
{
    if (!isset($_SESSION['customer'])) {
        header("Location: $loginUrl");
        exit();
    }
}

/** Any logged-in staff member (regular employee OR the super-admin account). */
function require_staff_login(string $loginUrl = 'login.php'): void
{
    if (!isset($_SESSION['admin'])) {
        header("Location: $loginUrl");
        exit();
    }
}

/** Only the super-admin account (email === 'admin'). */
function require_super_admin(string $loginUrl = 'login.php'): void
{
    require_staff_login($loginUrl);
    if ($_SESSION['admin'] !== 'admin') {
        http_response_code(403);
        header("Location: $loginUrl?error=unauthorised");
        exit();
    }
}

/** Reject the request outright (used by the AJAX gateway, not by full pages). */
function deny(int $code = 403, string $message = 'Access denied.'): void
{
    http_response_code($code);
    die($message);
}
