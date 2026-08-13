<?php

/**
 * Fix for V-01 (SQL Injection): every query below now uses a mysqli
 * prepared statement with bound parameters instead of concatenating
 * request data into the SQL string. Functions keep returning a
 * mysqli_result (via ->get_result()) so every existing call site
 * (mysqli_fetch_assoc / mysqli_num_rows / mysqli_fetch_all) elsewhere in
 * the app keeps working unchanged.
 *
 * Fix for V-04 (Plaintext Password Storage): password checks no longer
 * compare the raw password inside the SQL WHERE clause — they fetch the
 * stored bcrypt hash by identifier and verify it in PHP with
 * password_verify().
 */

function getAllBranch()
{
    include 'connection.php';

    $viewcat = "SELECT * FROM branch WHERE is_deleted = 0";
    return mysqli_query($con, $viewcat);
}
function getAllArea()
{
    include 'connection.php';

    $viewcat = "SELECT * FROM area WHERE is_deleted = 0";
    return mysqli_query($con, $viewcat);
}
function getAllAreabyID($area_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM area WHERE is_deleted = 0 AND area_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $area_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}
function getAllPrice()
{
    include 'connection.php';

    $viewcat = "SELECT * FROM price_table WHERE is_deleted = 0";
    return mysqli_query($con, $viewcat);
}

function checkPrice($start_area, $end_area)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM price_table WHERE is_deleted = 0 AND start_area = ? AND end_area = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $start_area, $end_area);
    mysqli_stmt_execute($stmt);
    return mysqli_num_rows(mysqli_stmt_get_result($stmt));
}

function getBille($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM request join customer on customer.customer_id = request.customer_id WHERE request.customer_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

//product

function getAllemployee()
{
    include 'connection.php';

    $q1 = "SELECT * FROM employee WHERE is_deleted = 0 AND email != 'admin'";
    return mysqli_query($con, $q1);
}

function getemployeeByID($emp_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM employee WHERE is_deleted = 0 AND emp_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $emp_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getemployeeByEmail($email)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM employee WHERE is_deleted = 0 AND email = ?");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getBranchByID($branch_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM branch WHERE is_deleted = 0 AND branch_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $branch_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getAllTrackingByCUS($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM request WHERE is_deleted = 0 AND customer_id = ? ORDER BY date_updated DESC");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

/** Fetch a single request row, scoped to the owning customer (IDOR fix). */
function getRequestByIdForCustomer($request_id, $customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM request WHERE is_deleted = 0 AND request_id = ? AND customer_id = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $request_id, $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getAllTracking()
{
    include 'connection.php';

    $viewcat = "SELECT * FROM request join customer on customer.customer_id = request.customer_id WHERE request.is_deleted = 0 ORDER BY date_updated DESC";
    return mysqli_query($con, $viewcat);
}

function checkemployeetByEmail($email)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM employee WHERE email = ? AND is_deleted = 0");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        return mysqli_num_rows($result);
    }

    $stmt2 = mysqli_prepare($con, "SELECT * FROM customer WHERE email = ? AND is_deleted = 0");
    mysqli_stmt_bind_param($stmt2, 's', $email);
    mysqli_stmt_execute($stmt2);
    $cus_res = mysqli_stmt_get_result($stmt2);

    return mysqli_num_rows($cus_res) > 0 ? mysqli_num_rows($cus_res) : 0;
}

function getAllgalleryImages()
{
    include 'connection.php';

    $q1 = "SELECT * FROM gallery";
    return mysqli_query($con, $q1);
}

//customer


/** Verifies a customer's current password (bcrypt). Echoes 1/0 like the old count-based contract. */
function checkuserPassword($data)
{
    include 'connection.php';
    $customer_id = $data['customer_id'];
    $password = $data['password'];

    $stmt = mysqli_prepare($con, "SELECT password FROM customer WHERE is_deleted = 0 AND customer_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

    echo ($row && password_verify($password, $row['password'])) ? 1 : 0;
}

function checkArea($data)
{
    include 'connection.php';

    $start_area = $data['send_location'];
    $end_area = $data['end_location'];

    $stmt = mysqli_prepare($con, "SELECT * FROM price_table WHERE is_deleted = 0 AND start_area = ? AND end_area = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $start_area, $end_area);
    mysqli_stmt_execute($stmt);
    $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
    echo $row ? $row['price'] : '';
}

function checkAreaByName($area_name)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM area WHERE area_name = ? AND is_deleted = 0");
    mysqli_stmt_bind_param($stmt, 's', $area_name);
    mysqli_stmt_execute($stmt);
    return mysqli_num_rows(mysqli_stmt_get_result($stmt));
}

function checkUserEmail($data)
{
    include 'connection.php';

    $customer_id = $data['customer_id'];
    $email = $data['email'];

    $stmt = mysqli_prepare($con, "SELECT * FROM customer WHERE is_deleted = 0 AND email = ? AND customer_id = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $email, $customer_id);
    mysqli_stmt_execute($stmt);
    $count = mysqli_num_rows(mysqli_stmt_get_result($stmt));
    echo $count;
}

function getAllcustomerById($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM customer WHERE is_deleted = '0' AND customer_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getAllcustomers()
{
    include 'connection.php';

    $q1 = "SELECT * FROM customer WHERE is_deleted = 0 AND email != 'admin'";
    return mysqli_query($con, $q1);
}

/**
 * Fix for V-04: fetch the candidate rows by email only, then verify the
 * bcrypt hash in PHP. Keeps the original "echo which role logged in, and
 * populate $_SESSION" contract used by server/api.php.
 */
function getLoginAdmin($data)
{
    include 'connection.php';

    $email = $data['email'];
    $password = $data['password'];

    $value = "";

    $stmt = mysqli_prepare($con, "SELECT * FROM employee WHERE email = ? AND is_deleted = 0");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    $employeeRow = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

    $stmt2 = mysqli_prepare($con, "SELECT * FROM customer WHERE email = ? AND is_deleted = 0");
    mysqli_stmt_bind_param($stmt2, 's', $email);
    mysqli_stmt_execute($stmt2);
    $customerRow = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt2));

    if ($employeeRow && password_verify($password, $employeeRow['password'])) {
        $value = 'admin';
        session_regenerate_id(true);
        $_SESSION['admin'] = $employeeRow['email'];
    } elseif ($customerRow && password_verify($password, $customerRow['password'])) {
        $value = 'customer';
        session_regenerate_id(true);
        $_SESSION['customer'] = $customerRow['customer_id'];
    }

    echo $value;
}

function checkemployee($email)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM employee WHERE email = ? AND is_deleted = '0'");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function checkCustomerByEmail($email)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM customer WHERE email = ? AND is_deleted = '0'");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}


function checkCustomerByID($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM customer WHERE customer_id = ? AND is_deleted = '0'");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getAllCustomer()
{
    include 'connection.php';

    $q1 = "SELECT * FROM customer WHERE is_deleted = '0' AND email != 'admin'";
    $table = mysqli_query($con, $q1);
    $columns = mysqli_fetch_all($table, MYSQLI_ASSOC);

    return $columns;
}


//contact

function getAllMessages()
{
    include 'connection.php';

    $messages = "SELECT * FROM contact";
    return mysqli_query($con, $messages);
}

//count

function dataCount($table)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    if (!is_allowed_table($table)) {
        return 0;
    }

    $stmt = mysqli_prepare($con, "SELECT * FROM `$table` WHERE is_deleted = 0");
    mysqli_stmt_execute($stmt);
    $count = mysqli_num_rows(mysqli_stmt_get_result($stmt));
    echo $count;
}

function dataCountWhere($table, $where)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    // $where here is always a hardcoded fragment supplied by trusted template
    // code (never raw request input) — validated against the table allow-list
    // as defence in depth for the identifier ($table).
    if (!is_allowed_table($table)) {
        echo 0;
        return;
    }

    $counts = "SELECT * FROM `$table` WHERE $where AND is_deleted = 0";
    $res = mysqli_query($con, $counts);
    $count = mysqli_num_rows($res);
    echo $count;
}

function dataforCount($table)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    if (!is_allowed_table($table)) {
        return false;
    }

    return mysqli_query($con, "SELECT sum(total) as sum FROM `$table` WHERE is_deleted = 0");
}

function dataforCountToday($table)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    if (!is_allowed_table($table)) {
        return false;
    }

    return mysqli_query($con, "SELECT sum(total) as sum FROM `$table` WHERE month(now()) = month(date_updated) AND is_deleted = 0");
}


//settings

function getAllSettings()
{
    include 'connection.php';

    $settings = "SELECT * FROM settings";
    return mysqli_query($con, $settings);
}

/** Verifies a staff member's current password (bcrypt). Echoes 1/0. */
function checkPasswordByName($data)
{
    include 'connection.php';
    $email = $data['email'];
    $password = $data['password'];

    $stmt = mysqli_prepare($con, "SELECT password FROM employee WHERE email = ?");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

    echo ($row && password_verify($password, $row['password'])) ? 1 : 0;
}

function getAllCart($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM cart join products on products.pid = cart.pid join customer on customer.customer_id = cart.customer_id WHERE cart.customer_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}


function getAllOrdersByCustomer($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM product_orders WHERE customer_id = ? AND is_deleted = '0' ORDER BY date_updated DESC");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getAllOrderItemsBYOrder($order_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM order_items join products on order_items.pid = products.pid WHERE order_items.order_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $order_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function getAllOrders()
{
    include 'connection.php';

    $viewcat = "SELECT * FROM product_orders join customer on customer.customer_id = product_orders.customer_id  WHERE product_orders.is_deleted = '0' ORDER BY date_updated DESC";
    return mysqli_query($con, $viewcat);
}

function getAllOrdersPending()
{
    include 'connection.php';

    $viewcat = "SELECT * FROM product_orders join customer on customer.customer_id = product_orders.customer_id  WHERE product_orders.is_deleted = '0' AND product_orders.order_status = '1' ORDER BY date_updated DESC";
    return mysqli_query($con, $viewcat);
}

function getAllOrderItems($order_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM order_items join products on order_items.pid = products.pid WHERE order_items.order_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $order_id);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}
