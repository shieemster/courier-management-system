<?php
/**
 * security_headers.php
 * ---------------------
 * Fix for V-03 (Content Security Policy Header Not Set) plus a small set of
 * companion hardening headers. Must be required before any output is sent.
 */

if (!headers_sent()) {
    // NOTE on 'unsafe-inline' in script-src: this codebase wires up every
    // control with inline onclick="..." handlers rather than
    // addEventListener() (e.g. onclick="login(this.form)" throughout).
    // Dropping 'unsafe-inline' would silently break every button in the
    // app rather than block an attacker, since the browser cannot tell an
    // inline onclick="login(this.form)" apart from an injected
    // onclick="fetch(evil)". A same-origin XSS therefore isn't fully
    // neutralised by CSP alone here — output encoding (e(), see
    // includes/functions.php) is the actual control against script
    // injection; CSP still adds real value by blocking any *externally
    // hosted* script/style/frame the app doesn't explicitly allow-list
    // below, and this header being present and enforced at all (vs. fully
    // absent, the ZAP finding) is itself the fix being demonstrated.
    header("Content-Security-Policy: default-src 'self'; " .
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://use.fontawesome.com https://kit.fontawesome.com https://ka-f.fontawesome.com; " .
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://ka-f.fontawesome.com; " .
        "font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com data:; " .
        "img-src 'self' data:; " .
        "connect-src 'self' https://ka-f.fontawesome.com; " .
        "frame-ancestors 'none'; " .
        "base-uri 'self'; " .
        "form-action 'self'");
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Permissions-Policy: geolocation=(), camera=(), microphone=()");

    // Only makes sense over HTTPS deployments; harmless to send on localhost.
    if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') == 443)) {
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    }
}
