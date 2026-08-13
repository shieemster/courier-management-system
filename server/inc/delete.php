<?php

/**
 * Fix for V-01 (SQL Injection): $table / $id_fild come from request data —
 * validated against the allow-list in table_whitelist.php before use as
 * identifiers; the id VALUE is always bound as a parameter.
 */

function deleteDataTables($data)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $id_fild = $data['id_fild'];
    $id = $data['id'];
    $table = $data['table'];

    if (!is_allowed_table($table) || !is_allowed_id_field($table, $id_fild)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "UPDATE `$table` SET is_deleted = '1' WHERE `$id_fild` = ?");
    mysqli_stmt_bind_param($stmt, 's', $id);
    return mysqli_stmt_execute($stmt);
}

function permanantDeleteDataTable($data)
{
    include 'connection.php';
    require_once 'table_whitelist.php';

    $id_fild = $data['id_fild'];
    $id = $data['id'];
    $table = $data['table'];

    if (!is_allowed_table($table) || !is_allowed_id_field($table, $id_fild)) {
        http_response_code(400);
        return false;
    }

    $stmt = mysqli_prepare($con, "DELETE FROM `$table` WHERE `$id_fild` = ?");
    mysqli_stmt_bind_param($stmt, 's', $id);
    return mysqli_stmt_execute($stmt);
}


function deleteAllCartItems($customer_id)
{
    include 'connection.php';

    $stmt = mysqli_prepare($con, "DELETE FROM cart WHERE customer_id = ?");
    mysqli_stmt_bind_param($stmt, 's', $customer_id);
    return mysqli_stmt_execute($stmt);
}


?>
