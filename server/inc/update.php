<?php

/**
 * Fix for V-01 (SQL Injection): $table / $field / $id_fild are request-
 * controlled *identifiers*, which can never be passed as bind_param values
 * — they must be validated against a known-safe allow-list before being
 * concatenated into the query. Only the actual VALUE is bound as a
 * parameter. See server/inc/table_whitelist.php.
 */

function updateDataTable($data)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $id_fild = $data['id_fild'];
    $id = $data['id'];
    $field = $data['field'];
    $value = $data['value'];
    $table = $data['table'];

    if (!is_allowed_table($table) || !is_allowed_id_field($table, $id_fild) || !is_allowed_column($table, $field)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE `$table` SET `$field` = ? WHERE `$id_fild` = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $value, $id);
    return mysqli_stmt_execute($stmt);
}


function updateSubCatData($data)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $id_fild = $data['id_fild'];
    $id = $data['id'];
    $field = $data['field'];
    $value = $data['value'];
    $table = $data['table'];

    $getdatas = getAllSubCategory($id);
    $count = mysqli_num_rows($getdatas);

    if ($count > 0) {
        echo $count;
        return;
    }

    if (!is_allowed_table($table) || !is_allowed_id_field($table, $id_fild) || !is_allowed_column($table, $field)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE `$table` SET `$field` = ? WHERE `$id_fild` = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $value, $id);
    return mysqli_stmt_execute($stmt);
}

function editImages($data, $img)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $id_fild = $data['id_fild'];
    $id = $data['id'];
    $field = $data['field'];
    $table = $data['table'];

    if (!is_allowed_table($table) || !is_allowed_id_field($table, $id_fild) || !is_allowed_column($table, $field)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE `$table` SET `$field` = ? WHERE `$id_fild` = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $img, $id);
    return mysqli_stmt_execute($stmt);
}

//qty reduce code

function productQtyReduce($pid, $qty)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "SELECT * FROM products WHERE pid = ?");
    mysqli_stmt_bind_param($stmt, 's', $pid);
    mysqli_stmt_execute($stmt);
    $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

    $value = $row['product_qty'] - $qty;

    $stmt2 = mysqli_prepare($con, "UPDATE products SET product_qty = ?, date_updated = now() WHERE pid = ?");
    mysqli_stmt_bind_param($stmt2, 'ss', $value, $pid);
    return mysqli_stmt_execute($stmt2);
}

function increaseQtyProduct($data)
{
    include 'connection.php';

    $serve_id = $data['serve_id'];

    $stmt = mysqli_prepare($con, "SELECT * FROM server_products WHERE serve_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $serve_id);
    mysqli_stmt_execute($stmt);
    $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

    $pid = $row['pid'];

    $stmt2 = mysqli_prepare($con, "SELECT * FROM products WHERE pid = ?");
    mysqli_stmt_bind_param($stmt2, 's', $pid);
    mysqli_stmt_execute($stmt2);
    $row2 = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt2));

    $value = $row['serve_qty'] + $row2['product_qty'];

    $stmt3 = mysqli_prepare($con, "UPDATE products SET product_qty = ?, date_updated = now() WHERE pid = ?");
    mysqli_stmt_bind_param($stmt3, 'ss', $value, $pid);
    return mysqli_stmt_execute($stmt3);
}

function changePageSettings($data)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $field = $data['field'];
    $value = $data['value'];

    if (!is_allowed_column('settings', $field)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE settings SET `$field` = ?");
    mysqli_stmt_bind_param($stmt, 's', $value);
    return mysqli_stmt_execute($stmt);
}

function editSettingImage($data, $img)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $field = $data['field'];

    if (!is_allowed_column('settings', $field)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE settings SET `$field` = ?");
    mysqli_stmt_bind_param($stmt, 's', $img);
    return mysqli_stmt_execute($stmt);
}

function editQtyinCart($data)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $cart_id = $data['cart_id'];
    $field = $data['field'];
    $value = $data['value'];

    if (!is_allowed_column('cart', $field)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE cart SET `$field` = ?, date_updated = now() WHERE cart_id = ?");
    mysqli_stmt_bind_param($stmt, 'ss', $value, $cart_id);
    return mysqli_stmt_execute($stmt);
}

?>
