<?php
/**
 * The actual login gate now runs in includes/bootstrap.php +
 * require_customer_login(), called at the very top of every page that
 * needs it — BEFORE any HTML (including pages/head.php's raw "<head>"
 * output) is sent. That ordering is what makes the redirect below
 * effective; previously this same check ran after output had already
 * started, so header() failed silently and the page rendered anyway
 * (the RBAC bypass documented in Part 1).
 *
 * This file is now just responsible for loading the current customer's
 * row once the guard has already passed. The isset() check is kept as a
 * defensive fallback in case this file is ever included on its own.
 */

if (!isset($_SESSION['customer'])) {
    header("Location: admin/login.php");
    exit();
}

$getall = getAllcustomerById($_SESSION['customer']);
$cus = mysqli_fetch_assoc($getall);
$customer_id = $cus['customer_id'];
