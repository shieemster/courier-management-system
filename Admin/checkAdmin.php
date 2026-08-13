<?php
/**
 * The real guard is require_super_admin(), called from includes/bootstrap.php
 * at the very top of the page. Kept as a defensive fallback only — see
 * Admin/admin.php for the explanation of why the old header()-after-output
 * pattern silently failed to protect these pages.
 */

if (!isset($_SESSION['admin']) || $_SESSION['admin'] !== 'admin') {
    header("Location: login.php");
    exit();
}
