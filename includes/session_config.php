<?php
/**
 * session_config.php
 * -------------------
 * Secure session bootstrap (V-02/CSRF support + general session hardening).
 * MUST be required before ANY byte of output is sent (no whitespace/HTML
 * before the opening <?php tag of the file that includes this one), because
 * ini_set('session.*', ...) and session_start() both fail silently once
 * headers have already been sent.
 *
 * This is also the fix for the RBAC bypass found in Part 1: the previous
 * app called session_start() *after* pages/head.php had already printed
 * "<head>" to the browser, so every later header("Location: ...") redirect
 * used for access control failed silently and the protected page rendered
 * anyway. Every entry point now requires this file first, before any markup.
 */

if (session_status() === PHP_SESSION_NONE) {
    // Harden the session cookie itself.
    ini_set('session.cookie_httponly', '1');   // JS (and therefore XSS) cannot read the cookie
    ini_set('session.cookie_samesite', 'Strict'); // mitigates CSRF at the cookie level
    ini_set('session.use_strict_mode', '1');   // reject uninitialised session IDs
    ini_set('session.gc_maxlifetime', '1800'); // 30 minute server-side lifetime

    // Only require HTTPS cookies when we are actually being served over HTTPS.
    // (Forcing this on a plain XAMPP http://localhost dev box would break login entirely.)
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443)
        || ((($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'));
    ini_set('session.cookie_secure', $isHttps ? '1' : '0');

    session_start();
}

// Idle-timeout enforcement (30 minutes of inactivity).
if (isset($_SESSION['last_active']) && (time() - $_SESSION['last_active']) > 1800) {
    $_SESSION = [];
    session_unset();
    session_destroy();
    session_start();
}
$_SESSION['last_active'] = time();
