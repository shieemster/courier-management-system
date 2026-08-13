<?php
/**
 * csrf_helper.php
 * ----------------
 * Fix for V-02 (Absence of Anti-CSRF Tokens). Synchroniser-token pattern.
 * Requires an active session (include session_config.php first).
 */

function generate_csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(generate_csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

function validate_csrf_token(?string $token): bool
{
    return isset($_SESSION['csrf_token'])
        && is_string($token)
        && $token !== ''
        && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Call from any POST handler that mutates state. Dies with 403 on failure.
 */
function require_csrf_token(): void
{
    $token = $_POST['csrf_token'] ?? '';
    if (!validate_csrf_token($token)) {
        http_response_code(403);
        die('Invalid or missing CSRF token.');
    }
}
