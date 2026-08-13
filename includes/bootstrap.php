<?php
/**
 * bootstrap.php
 * --------------
 * Single entry point every page includes as its very first statement,
 * before any HTML/whitespace is emitted. Wires up hardened sessions,
 * security response headers, CSRF helpers and output-encoding helpers.
 */

require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/security_headers.php';
require_once __DIR__ . '/csrf_helper.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/guards.php';
