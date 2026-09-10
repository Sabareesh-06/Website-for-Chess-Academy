<?php
session_start();

$cn30 = mysqli_connect("localhost", "root", "", "30mm");

if (!$cn30) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Database unavailable.");
}

mysqli_set_charset($cn30, "utf8mb4");

if (!isset($_SESSION['role'], $_SESSION['Username'])) {
    header("Location: login.php");
    exit();
}

$studentId = intval($_GET['id'] ?? 0);
$action = isset($_GET['action']) && $_GET['action'] === 'download' ? 'download' : 'view';

$viewerUsername = $_SESSION['Username'];
$viewerRole = $_SESSION['role'];

/* --------------------
   GET VIEWER ID
-------------------- */
$viewerId = 0;

$stmt = mysqli_prepare($cn30, "SELECT ID FROM register WHERE Username = ? LIMIT 1");

if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $viewerUsername);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);
    $viewer = mysqli_fetch_assoc($result);

    if ($viewer) {
        $viewerId = (int)$viewer['ID'];
    }

    mysqli_stmt_close($stmt);
}

/* --------------------
   GET CERTIFICATE OWNER
-------------------- */
if ($studentId <= 0) {
    die("Invalid certificate request.");
}

$stmt = mysqli_prepare(
    $cn30,
    "SELECT ID, Username, Name, role, birth_certificate
     FROM register
     WHERE ID = ?
     LIMIT 1"
);

if (!$stmt) {
    die("Database error.");
}

mysqli_stmt_bind_param($stmt, "i", $studentId);
mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);
$owner = mysqli_fetch_assoc($result);

mysqli_stmt_close($stmt);

if (!$owner || empty($owner['birth_certificate'])) {
    die("Certificate not found.");
}

/* --------------------
   PERMISSION CHECK
-------------------- */
$isSelf = hash_equals((string)$owner['Username'], (string)$viewerUsername);

$canAccess =
    in_array($viewerRole, ['admin', 'master'], true)
    ||
    (
        $isSelf &&
        in_array($viewerRole, ['student', 'user'], true)
    );

if (!$canAccess) {
    die("Access denied.");
}

/* --------------------
   LOG VIEW / DOWNLOAD
-------------------- */
$logStmt = mysqli_prepare(
    $cn30,
    "INSERT INTO certificate_view_logs
    (student_id, viewer_id, viewer_username, viewer_role, action)
    VALUES (?, ?, ?, ?, ?)"
);

if ($logStmt) {
    mysqli_stmt_bind_param(
        $logStmt,
        "iisss",
        $owner['ID'],
        $viewerId,
        $viewerUsername,
        $viewerRole,
        $action
    );

    mysqli_stmt_execute($logStmt);
    mysqli_stmt_close($logStmt);
}

/* --------------------
   SERVE FILE SAFELY
-------------------- */
$filePath = $owner['birth_certificate'];

if (!is_file($filePath)) {
    die("Certificate file is missing.");
}

$realPath = realpath($filePath);
$basePath = realpath(__DIR__);

if ($realPath === false || $basePath === false || strpos($realPath, $basePath) !== 0) {
    die("Invalid certificate path.");
}

$ext = strtolower(pathinfo($realPath, PATHINFO_EXTENSION));
$allowedExt = ['pdf', 'jpg', 'jpeg', 'png'];

if (!in_array($ext, $allowedExt, true)) {
    die("Invalid certificate file type.");
}

$mimeMap = [
    'pdf' => 'application/pdf',
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png' => 'image/png'
];

$mime = function_exists('mime_content_type')
    ? mime_content_type($realPath)
    : ($mimeMap[$ext] ?? 'application/octet-stream');

if (empty($mime)) {
    $mime = $mimeMap[$ext] ?? 'application/octet-stream';
}

$fileName = "birth_certificate_" . (int)$owner['ID'] . "." . $ext;

header("Content-Type: " . $mime);
header("Content-Length: " . filesize($realPath));
header("Cache-Control: private, max-age=0, must-revalidate");

if ($action === 'download') {
    header('Content-Disposition: attachment; filename="' . $fileName . '"');
} else {
    header('Content-Disposition: inline; filename="' . $fileName . '"');
}

readfile($realPath);
exit();