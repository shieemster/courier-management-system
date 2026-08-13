<?php

/**
 * server/api.php — AJAX gateway
 * ------------------------------
 * This single dispatcher backs almost every mutating action in the app
 * (login, password/email change, admin CRUD, request creation, ...).
 * Before the fix, EVERY case here was reachable by an unauthenticated
 * visitor sending a raw POST — including updateData/deleteData/
 * permanantDeleteData, which accept the target table/column name straight
 * from the client (see server/inc/table_whitelist.php for the SQLi side of
 * that). That combination let anyone rewrite any row in any table,
 * including `UPDATE employee SET password = ... WHERE email = 'admin'`.
 *
 * Fix for V-02 (CSRF) + Fix 5 (RBAC) + IDOR protection: every mutating
 * function_code now (a) validates the synchroniser CSRF token and (b) is
 * gated behind the correct session role, with row-ownership enforced where
 * the action touches "my own" data (password/email self-service, request
 * creation, cart).
 */

require_once __DIR__ . '/../includes/bootstrap.php';

include 'inc/get.php';
include 'inc/connection.php';
include 'inc/update.php';
include 'inc/delete.php';
include 'inc/add.php';

$action = $_GET['function_code'] ?? '';

// Actions any visitor may call without being logged in.
$PUBLIC_ACTIONS = ['login', 'addCustomer', 'addcontact', 'checkArea'];

// Actions restricted to staff (regular employee or the super-admin account).
$STAFF_ACTIONS = [
    'getCustomerTbleData', 'insertImageUpload', 'imageUploadProducts', 'addProducts',
    'deleteData', 'permanantDeleteData', 'changesettings', 'SettingImage',
    'checkPasswordByEmail', 'addEmployee', 'addBranch', 'addPrice', 'addArea',
];

// Actions restricted to a logged-in customer.
$CUSTOMER_ACTIONS = ['editQty', 'checkEmail', 'checkPassword', 'addRequest'];

// All state-changing actions require a valid CSRF token. Read-only lookups
// (checkArea, checkEmail, checkPassword, checkPasswordByEmail,
// getCustomerTbleData) are exempt since they don't mutate data, but they
// still require the auth checks above.
$CSRF_EXEMPT = ['checkArea', 'checkEmail', 'checkPassword', 'checkPasswordByEmail', 'getCustomerTbleData'];

if (in_array($action, $STAFF_ACTIONS, true)) {
    if (!isset($_SESSION['admin'])) {
        deny(401, 'Staff login required.');
    }
} elseif (in_array($action, $CUSTOMER_ACTIONS, true)) {
    if (!isset($_SESSION['customer'])) {
        deny(401, 'Customer login required.');
    }
} elseif ($action === 'updateData' || $action === 'checkArea') {
    // handled with bespoke ownership logic below (updateData) or public-but-scoped (checkArea)
    if ($action === 'checkArea' && !isset($_SESSION['customer']) && !isset($_SESSION['admin'])) {
        deny(401, 'Login required.');
    }
} elseif (!in_array($action, $PUBLIC_ACTIONS, true) && $action !== '') {
    deny(404, 'Unknown action.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !in_array($action, $CSRF_EXEMPT, true)) {
    require_csrf_token();
}

if ($action === 'getCustomerTbleData') {
    echo json_encode(getAllCustomer());
} else if ($action === 'updateData') {

    // updateData is the generic admin CRUD endpoint. Only two self-service
    // uses are allowed for a plain customer/staff session (change my own
    // password/email); everything else requires a staff session.
    $table = $_POST['table'] ?? '';
    $id_fild = $_POST['id_fild'] ?? '';
    $id = $_POST['id'] ?? '';

    $isSelfCustomer = isset($_SESSION['customer'])
        && $table === 'customer' && $id_fild === 'customer_id' && (string) $id === (string) $_SESSION['customer'];
    $isSelfStaff = isset($_SESSION['admin'])
        && $table === 'employee' && $id_fild === 'email' && (string) $id === (string) $_SESSION['admin'];
    // IDOR fix: a customer may cancel a request (table=request, field=tracking_status)
    // only when that request actually belongs to them — the old endpoint let any
    // logged-in customer cancel any other customer's shipment by guessing request_id.
    $isOwnRequest = isset($_SESSION['customer'])
        && $table === 'request' && $id_fild === 'request_id'
        && mysqli_num_rows(getRequestByIdForCustomer($id, $_SESSION['customer'])) === 1;
    $isStaff = isset($_SESSION['admin']);

    if (!$isSelfCustomer && !$isSelfStaff && !$isOwnRequest && !$isStaff) {
        deny(403, 'You may only update your own record.');
    }

    updateDataTable($_POST);
} else if ($action === 'insertImageUpload') {

    $img = $_FILES['file']['name'];
    $target_dir = "uploads/gallery/";
    $target_file = $target_dir . basename($img);
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    $extensions_arr = array("jpg", "jpeg", "png", "gif", "jfif", "svg", "webp");

    if (in_array($imageFileType, $extensions_arr)) {
        move_uploaded_file($_FILES['file']['tmp_name'], $target_dir . basename($img));
        insertImagetoGallery(basename($img));
    }
} else if ($action === 'imageUploadProducts') {

    $img = $_FILES['file']['name'];
    $target_dir = "uploads/products/";
    $target_file = $target_dir . basename($img);
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    $extensions_arr = array("jpg", "jpeg", "png", "gif", "jfif", "svg", "webp");

    if (in_array($imageFileType, $extensions_arr)) {
        move_uploaded_file($_FILES['file']['tmp_name'], $target_dir . basename($img));
        editImages($_POST, basename($img));
    }
} else if ($action === 'addProducts') {

    $img = $_FILES['file']['name'];
    $target_dir = "uploads/products/";
    $target_file = $target_dir . basename($img);
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    $extensions_arr = array("jpg", "jpeg", "png", "gif", "jfif", "svg", "webp");
} else if ($action === 'deleteData') {
    deleteDataTables($_POST);
} else if ($action === 'permanantDeleteData') {
    permanantDeleteDataTable($_POST);
} else if ($action === 'changesettings') {
    changePageSettings($_POST);
} else if ($action === 'SettingImage') {

    $img = $_FILES['file']['name'];
    $target_dir = "uploads/settings/";
    $target_file = $target_dir . basename($img);
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    $extensions_arr = array("jpg", "jpeg", "png", "gif", "jfif", "svg", "webp");

    if (in_array($imageFileType, $extensions_arr)) {
        move_uploaded_file($_FILES['file']['tmp_name'], $target_dir . basename($img));
        editSettingImage($_POST, basename($img));
    }
} else if ($action === 'login') {
    echo getLoginAdmin($_POST);
} else if ($action === 'checkPasswordByEmail') {
    // Self-service only: staff may only verify their own current password.
    if (($_POST['email'] ?? '') !== $_SESSION['admin']) {
        deny(403);
    }
    checkPasswordByName($_POST);
} else if ($action === 'editQty') {
    editQtyinCart($_POST);
} else if ($action === 'addcontact') {
    addMessage($_POST);
} else if ($action === 'addCustomer') {
    createCustomer($_POST);
} else if ($action === 'checkEmail') {
    // Self-service only: a customer may only verify their own current email.
    if (($_POST['customer_id'] ?? '') !== (string) $_SESSION['customer']) {
        deny(403);
    }
    checkUserEmail($_POST);
} else if ($action === 'checkPassword') {
    // Self-service only: a customer may only verify their own current password.
    if (($_POST['customer_id'] ?? '') !== (string) $_SESSION['customer']) {
        deny(403);
    }
    checkuserPassword($_POST);
} else if ($action === 'addEmployee') {
    if ($_SESSION['admin'] !== 'admin') {
        deny(403, 'Only the administrator may create staff accounts.');
    }
    addEmployee($_POST);
} else if ($action === 'addBranch') {
    addBranch($_POST);
} else if ($action === 'addPrice') {
    addPrice($_POST);
} else if ($action === 'checkArea') {
    checkArea($_POST);
} else if ($action === 'addArea') {
    addArea($_POST);
} else if ($action === 'addRequest') {
    // IDOR fix: force customer_id from the session, never trust the client.
    $requestData = $_POST;
    $requestData['customer_id'] = $_SESSION['customer'];
    addRequest($requestData);
}
