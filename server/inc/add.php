<?php

/**
 * Fix for V-01 (SQL Injection): prepared statements with bound parameters.
 * Fix for V-04 (Plaintext Password Storage): password_hash() (bcrypt) before
 * any password is written to the database.
 */

function insertImagetoGallery($img)
{
	include 'connection.php';

	$stmt = mysqli_prepare($con, "INSERT INTO gallery(gallery_image) VALUES(?)");
	mysqli_stmt_bind_param($stmt, 's', $img);
	return mysqli_stmt_execute($stmt);
}

function addBranch($data)
{
	include 'connection.php';

	$branch_name = $data['branch_name'];
	$stmt = mysqli_prepare($con, "INSERT INTO branch(branch_name, is_deleted) VALUES(?, 0)");
	mysqli_stmt_bind_param($stmt, 's', $branch_name);
	return mysqli_stmt_execute($stmt);
}

function addArea($data)
{
	include 'connection.php';

	$area_name = $data['area_name'];

	$count = checkAreaByName($area_name);

	if ($count == 0) {
		$stmt = mysqli_prepare($con, "INSERT INTO area(area_name, is_deleted) VALUES(?, 0)");
		mysqli_stmt_bind_param($stmt, 's', $area_name);
		return mysqli_stmt_execute($stmt);
	} else {
		echo json_encode($count);
	}
}

function addPrice($data)
{
	include 'connection.php';

	$start_area = $data['start_area'];
	$end_area = $data['end_area'];
	$price = $data['price'];

	$count = checkPrice($start_area, $end_area);

	if ($count == 0) {
		$stmt = mysqli_prepare($con, "INSERT INTO price_table(start_area, end_area, price, is_deleted, date_updated) VALUES(?, ?, ?, 0, now())");
		mysqli_stmt_bind_param($stmt, 'sss', $start_area, $end_area, $price);
		return mysqli_stmt_execute($stmt);
	} else {
		echo json_encode($count);
	}
}

function addRequest($data)
{
	include 'connection.php';

	$customer_id = $data['customer_id'];
	$sender_phone = $data['sender_phone'];
	$weight = $data['weight'];
	$send_location = $data['send_location'];
	$end_location = $data['end_location'];
	$total_fee = $data['total_fee'];
	$res_phone = $data['res_phone'];
	$red_address = $data['red_address'];
	$res_name = $data['res_name'];

	$stmt = mysqli_prepare($con, "INSERT INTO request(customer_id, sender_phone, weight, send_location, end_location, total_fee, res_phone, red_address, is_deleted, date_updated, tracking_status, res_name)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, 0, now(), 1, ?)");
	mysqli_stmt_bind_param(
		$stmt,
		'ssssssss' . 's',
		$customer_id,
		$sender_phone,
		$weight,
		$send_location,
		$end_location,
		$total_fee,
		$res_phone,
		$red_address,
		$res_name
	);
	return mysqli_stmt_execute($stmt);
}

function addEmployee($data)
{
	include 'connection.php';

	$name = $data['name'];
	$email = $data['email'];
	$phone = $data['phone'];
	$nic = $data['nic'];
	$address = $data['address'];
	$gender = $data['gender'];
	$password = password_hash($data['password'], PASSWORD_BCRYPT, ['cost' => 12]);
	$branch_id = $data['branch_id'];

	$count = checkemployeetByEmail($email);

	if ($count == 0) {
		$stmt = mysqli_prepare($con, "INSERT INTO employee(name, email, phone, nic, address, gender, password, is_deleted, branch_id) VALUES(?, ?, ?, ?, ?, ?, ?, 0, ?)");
		mysqli_stmt_bind_param($stmt, 'sssssssi', $name, $email, $phone, $nic, $address, $gender, $password, $branch_id);
		return mysqli_stmt_execute($stmt);
	} else {
		echo json_encode($count);
	}
}


//contact
function addMessage($data)
{
	include 'connection.php';

	$name = $data['name'];
	$email = $data['email'];
	$subject = $data['subject'];
	$message = $data['message'];

	$stmt = mysqli_prepare($con, "INSERT INTO contact(name, email, subject, message, date_updated) VALUES(?, ?, ?, ?, now())");
	mysqli_stmt_bind_param($stmt, 'ssss', $name, $email, $subject, $message);
	return mysqli_stmt_execute($stmt);
}


function createCustomer($data)
{
	include 'connection.php';

	$name = $data['name'];
	$email = $data['email'];
	$phone = $data['phone'];
	$nic = $data['nic'];
	$address = $data['address'];
	$gender = $data['gender'];
	$password = password_hash($data['password'], PASSWORD_BCRYPT, ['cost' => 12]);

	$stmt = mysqli_prepare($con, "INSERT INTO customer(name, email, phone, nic, address, gender, password, is_deleted) VALUES(?, ?, ?, ?, ?, ?, ?, 0)");
	mysqli_stmt_bind_param($stmt, 'sssssss', $name, $email, $phone, $nic, $address, $gender, $password);
	return mysqli_stmt_execute($stmt);
}
