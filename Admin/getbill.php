<?php
/**
 * Fix for the unauthenticated IDOR found here: this endpoint used to accept
 * ?customer_id=<anything> with NO session check at all, so any visitor
 * (logged in or not) could download any other customer's shipment receipt
 * (name, email, phone, address, parcel details) just by changing the
 * number in the URL.
 *
 * Now: a logged-in customer may only ever generate their own bill (the
 * session id is used directly, the query-string value is ignored); staff
 * may generate a bill for any customer.
 */
require_once __DIR__ . '/../includes/bootstrap.php';

if (isset($_SESSION['customer'])) {
    $customer_id = $_SESSION['customer'];
} elseif (isset($_SESSION['admin'])) {
    $customer_id = $_REQUEST['customer_id'] ?? '';
    if ($customer_id === '') {
        deny(400, 'customer_id is required.');
    }
} else {
    deny(401, 'Login required.');
}

require('assets/plugin/pdf/fpdf.php');
include('../server/api.php');

class PDF extends FPDF
{
    // Load data
    function BasicTable($customer_id)
    {
        $data = getBille($customer_id);

        $sum = 0;
        if ($row = mysqli_fetch_assoc($data)) {
            $sum++;
            $this->Ln();
            $this->Cell(70, 6, 'Courier Reference : #' . $row['request_id']);
            $this->Ln();
            $this->Cell(70, 6, 'Name : ' . $row['name']);
            $this->Ln();
            $this->Cell(70, 6, 'Email : ' . $row['email']);
            $this->Ln();
            $this->Cell(70, 6, 'Phone Number : ' . $row['phone']);
            $this->Ln();
            $this->Cell(70, 6, 'Courier Date : ' . $row['date_updated']);
            $this->Ln();
            $this->Ln();
            $this->Cell(70, 6, 'Weight : ' . $row['weight']);
            $this->Ln();
            $this->Cell(70, 6, 'Receiver Address : ' . $row['red_address']);
            $this->Ln();
            $this->Cell(70, 6, 'Receiver Phone: ' . $row['res_phone']);
            $this->Ln();
            $this->Ln();
            $this->Cell(60, 10, 'Total Fee : Rs.' . $row['total_fee'] . '.00');
        }
    }
}

$pdf = new PDF();
// Column headings
// Data loading
$pdf->SetFont('Arial', '', 14);
$pdf->AddPage();
$pdf->Cell(80);
$pdf->Cell(30, 10, 'Royal Express', 2, 0, 'C');
$pdf->Ln();
$pdf->Cell(80);
$pdf->Cell(30, 10, 'Your Receipt', 2, 0, 'C');
$pdf->Ln();
$pdf->Cell(80);
$pdf->Cell(30, 10, date("Y-M-d-D"), 2, 0, 'C');
$pdf->Ln();
$pdf->BasicTable($customer_id);
$pdf->Output();
