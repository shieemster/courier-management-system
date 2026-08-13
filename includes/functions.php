<?php
/**
 * functions.php
 * --------------
 * Small shared helpers. e() is the output-encoding fix used at every point
 * where user-supplied / DB-stored data is echoed back into HTML, to prevent
 * stored/reflected XSS.
 */

if (!function_exists('e')) {
    function e($value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
