<?php
/**
 * connection.php
 * ---------------
 * Fix for V-01 (SQL Injection) groundwork + removes hardcoded credentials
 * from source (Fix 1). Exposes:
 *   - $con : mysqli connection used with prepared statements (bind_param)
 *            throughout server/inc/{get,add,update,delete}.php, so every
 *            existing mysqli_fetch_assoc()/mysqli_num_rows() call site in
 *            the rest of the app keeps working unchanged.
 *   - $pdo : PDO connection, used by the auth-critical login path and by
 *            IDOR-sensitive lookups (matches the PDO pattern shown in the
 *            assignment's secure-coding exhibit).
 *
 * Credentials are read from environment variables when present (set these
 * in your Apache/XAMPP vhost or a .env loader for anything beyond local
 * dev) and fall back to the original local XAMPP defaults otherwise.
 */

$DB_HOST = getenv('DB_HOST') ?: 'localhost';
$DB_NAME = getenv('DB_NAME') ?: 'royal_express_db';
$DB_USER = getenv('DB_USER') ?: 'root';
$DB_PASS = getenv('DB_PASS') ?: '';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $con = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    mysqli_set_charset($con, 'utf8mb4');
} catch (mysqli_sql_exception $e) {
    error_log('Database connection failed: ' . $e->getMessage());
    http_response_code(500);
    die('Database connection failed.');
}

try {
    $pdo = new PDO(
        "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4",
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (PDOException $e) {
    error_log('PDO connection failed: ' . $e->getMessage());
    http_response_code(500);
    die('Database connection failed.');
}
