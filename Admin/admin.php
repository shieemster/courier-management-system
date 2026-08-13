<?php
/**
 * The real guard is require_staff_login(), called from includes/bootstrap.php
 * at the very top of every Admin/*.php page, before pages/head.php prints
 * any HTML. That ordering (and the exit() inside the guard) is what fixes
 * the RBAC bypass from Part 1 — the previous header("Location: ...") here
 * ran after output had already started, so it failed silently and the page
 * rendered anyway. This file is kept as a defensive fallback only.
 */

if (!isset($_SESSION['admin'])) {
    header("Location: login.php");
    exit();
}
