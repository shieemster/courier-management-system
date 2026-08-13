<?php
/**
 * table_whitelist.php
 * ---------------------
 * SQL identifiers (table/column names) can NEVER be bound as prepared
 * statement parameters — only values can. The old code interpolated
 * $_POST['table'] / $_POST['field'] / $_POST['id_fild'] straight into the
 * query string for the generic admin CRUD helpers (updateDataTable,
 * deleteDataTables, permanantDeleteDataTable, dataCount, dataCountWhere),
 * which meant an attacker controlled not just the value but the table and
 * column being written to — full-database SQL injection reachable from an
 * unauthenticated POST to server/api.php.
 *
 * This allow-list is the fix: every dynamic table/column name is validated
 * against a known-safe set before it is ever concatenated into SQL. Values
 * are still always bound via bind_param()/PDO placeholders.
 */

const ALLOWED_TABLES = [
    'branch'      => ['id_field' => 'branch_id',   'columns' => ['branch_name', 'is_deleted']],
    'area'        => ['id_field' => 'area_id',     'columns' => ['area_name', 'is_deleted']],
    'price_table' => ['id_field' => 'price_id',    'columns' => ['start_area', 'end_area', 'price', 'is_deleted', 'date_updated']],
    'employee'    => [
        'id_field'      => 'emp_id',
        'alt_id_fields' => ['email'], // self-service password change identifies by email
        'columns'       => ['name', 'email', 'phone', 'nic', 'address', 'gender', 'password', 'is_deleted', 'branch_id'],
    ],
    'customer'    => ['id_field' => 'customer_id', 'columns' => ['name', 'email', 'phone', 'nic', 'address', 'gender', 'password', 'is_deleted']],
    'request'     => ['id_field' => 'request_id',  'columns' => ['tracking_status', 'is_deleted']],
    'gallery'     => ['id_field' => 'gallery_id',  'columns' => ['gallery_image']],
    'cart'        => ['id_field' => 'cart_id',     'columns' => ['qty']],
    'contact'     => ['id_field' => 'contact_id',  'columns' => []],
    'settings'    => ['id_field' => null,          'columns' => ['header_image', 'header_title', 'header_desc', 'about_title', 'about_desc', 'company_phone', 'company_email', 'company_address', 'sub_image', 'about_image', 'link_facebook', 'link_twiiter', 'link_instragram', 'background_image']],
];

/** Is $table a known table and $idField a valid identifier column for it? */
function is_allowed_id_field(string $table, string $idField): bool
{
    if (!isset(ALLOWED_TABLES[$table])) {
        return false;
    }
    $def = ALLOWED_TABLES[$table];
    $valid = array_merge(
        $def['id_field'] !== null ? [$def['id_field']] : [],
        $def['alt_id_fields'] ?? []
    );
    return in_array($idField, $valid, true);
}

/** Is $field a known, updatable column on $table? */
function is_allowed_column(string $table, string $field): bool
{
    if (!isset(ALLOWED_TABLES[$table])) {
        return false;
    }
    return in_array($field, ALLOWED_TABLES[$table]['columns'], true);
}

function is_allowed_table(string $table): bool
{
    return isset(ALLOWED_TABLES[$table]);
}
