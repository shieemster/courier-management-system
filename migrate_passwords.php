<?php
/**
 * migrate_passwords.php — ONE-TIME USE ONLY
 * -------------------------------------------
 * Fix for V-04 (Plaintext Password Storage).
 *
 * The seed data in Database/royal_express_db.sql stores every password in
 * plain text (e.g. customer 'testuser1' / password 'testuser1', the admin
 * account 'admin' / password '12345'). Once login/registration switch to
 * password_hash()/password_verify(), those existing plaintext rows can no
 * longer log in — this script re-hashes them in place, once.
 *
 * HOW TO RUN
 *   1. Start Apache + MySQL in XAMPP.
 *   2. Visit http://localhost/courier-management-system/migrate_passwords.php
 *      in a browser (or `php migrate_passwords.php` from the project root).
 *   3. Confirm the "N password(s) migrated" output for both tables.
 *   4. DELETE this file (or move it outside the webroot). Leaving a script
 *      that rewrites every password hash reachable over HTTP is itself a
 *      vulnerability — it must not exist in the deployed/graded copy.
 *
 * Safe to re-run: any value that already looks like a bcrypt hash
 * ($2y$... / 60 chars) is skipped instead of being re-hashed.
 */

require_once __DIR__ . '/server/inc/connection.php';

function looksAlreadyHashed(string $value): bool
{
    return (bool) preg_match('/^\$2[aby]\$\d{2}\$/', $value);
}

function migrateTable(mysqli $con, string $table, string $idColumn): int
{
    $migrated = 0;
    $result = mysqli_query($con, "SELECT `$idColumn`, password FROM `$table`");
    while ($row = mysqli_fetch_assoc($result)) {
        if (looksAlreadyHashed($row['password'])) {
            continue;
        }
        $hash = password_hash($row['password'], PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = mysqli_prepare($con, "UPDATE `$table` SET password = ? WHERE `$idColumn` = ?");
        mysqli_stmt_bind_param($stmt, 'ss', $hash, $row[$idColumn]);
        mysqli_stmt_execute($stmt);
        $migrated++;
    }
    return $migrated;
}

$customerCount = migrateTable($con, 'customer', 'customer_id');
$employeeCount = migrateTable($con, 'employee', 'emp_id');

header('Content-Type: text/plain');
echo "Password migration complete.\n";
echo "customer table: {$customerCount} password(s) migrated to bcrypt.\n";
echo "employee table: {$employeeCount} password(s) migrated to bcrypt.\n";
echo "\nDelete this file now — it should never be present in the deployed app.\n";
